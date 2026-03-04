use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context, Result};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::Interval;
use walkdir::WalkDir;

/// Represents the type of integrity violation that occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FIMViolationType {
    HashMismatch,
    SizeChange,
    UnauthorizedDeletion,
    UnauthorizedCreation,
    PermissionChange,
    OwnershipChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBaseline {
    pub path: PathBuf,
    pub sha256_hash: String,
    pub size: u64,
    pub modified_time: SystemTime,
    pub baseline_timestamp: SystemTime,
}

/// A detected integrity violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FIMViolation {
    pub path: PathBuf,
    pub violation_type: FIMViolationType,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub detected_at: SystemTime,
}

/// Configuration for the FIM engine.
#[derive(Debug, Clone)]
pub struct FIMConfig {
    pub enabled: bool,
    pub scan_interval: Duration,
    pub monitored_paths: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>, // lowercase, including dot, e.g. ".log"
}

/// Reporter trait: lets you plug in your existing backend client.
#[async_trait::async_trait]
pub trait FIMReporter: Send + Sync + 'static {
    async fn report_violation(&self, violation: FIMViolation) -> Result<()>;
    async fn sync_baseline(&self, baseline: &HashMap<PathBuf, FileBaseline>) -> Result<()>;
}

/// Main FIM engine.
pub struct FIMEngine<R: FIMReporter> {
    config: FIMConfig,
    baseline_db: Arc<Mutex<HashMap<PathBuf, FileBaseline>>>,
    reporter: Arc<R>,
}

impl<R: FIMReporter> FIMEngine<R> {
    pub fn new(config: FIMConfig, reporter: Arc<R>) -> Self {
        Self {
            config,
            baseline_db: Arc::new(Mutex::new(HashMap::new())),
            reporter,
        }
    }

    /// Establish initial baseline by hashing all monitored files.
    pub async fn establish_baseline(&self) -> Result<usize> {
        if !self.config.enabled {
            info!("FIM disabled; skipping baseline establishment");
            return Ok(0);
        }

        let mut total_count = 0usize;
        let mut new_baseline = HashMap::new();

        for root in &self.config.monitored_paths {
            if !root.exists() {
                warn!("FIM monitored path does not exist: {}", root.display());
                continue;
            }

            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();

                if self.is_excluded(path) {
                    continue;
                }

                match self.build_baseline_for_file(path).await {
                    Ok(baseline) => {
                        new_baseline.insert(path.to_path_buf(), baseline);
                        total_count += 1;
                    }
                    Err(e) => {
                        warn!("FIM: failed to baseline {}: {:#}", path.display(), e);
                    }
                }
            }
        }

        {
            let mut guard = self
                .baseline_db
                .lock()
                .map_err(|_| anyhow!("FIM baseline lock poisoned"))?;
            *guard = new_baseline;
        }

        // Best-effort sync to backend
        if let Err(e) = self
            .reporter
            .sync_baseline(&self.baseline_snapshot()?)
            .await
        {
            error!("FIM: failed to sync baseline to backend: {:#}", e);
        }

        info!("FIM baseline established for {} files", total_count);
        Ok(total_count)
    }

    /// Start continuous validation loop as a Tokio task.
    ///
    /// Call this once from your agent main after baseline is established:
    /// `tokio::spawn(fim_engine.run_continuous_validation());`
    pub async fn run_continuous_validation(&self) -> Result<()> {
        if !self.config.enabled {
            info!("FIM disabled; not starting validation loop");
            return Ok(());
        }

        let mut interval: Interval = tokio::time::interval(self.config.scan_interval);

        loop {
            interval.tick().await;
            if let Err(e) = self.validate_all_once().await {
                error!("FIM validation cycle failed: {:#}", e);
            }
        }
    }

    /// Performs one validation cycle over all baseline entries.
    pub async fn validate_all_once(&self) -> Result<()> {
        let baseline_snapshot = self.baseline_snapshot()?;
        for (path, baseline) in baseline_snapshot {
            match self.validate_file(&path, &baseline).await {
                Ok(Some(violation)) => {
                    warn!(
                        "FIM violation: {:?} at {}",
                        violation.violation_type,
                        violation.path.display()
                    );

                    if let Err(e) = self.reporter.report_violation(violation).await {
                        error!("FIM: failed to report violation to backend: {:#}", e);
                    }
                }
                Ok(None) => {
                    // ok
                }
                Err(e) => {
                    warn!("FIM: validation error for {}: {:#}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Validate a single file against its baseline.
    async fn validate_file(
        &self,
        path: &Path,
        baseline: &FileBaseline,
    ) -> Result<Option<FIMViolation>> {
        // File deleted?
        if !path.exists() {
            return Ok(Some(FIMViolation {
                path: path.to_path_buf(),
                violation_type: FIMViolationType::UnauthorizedDeletion,
                expected_hash: Some(baseline.sha256_hash.clone()),
                actual_hash: None,
                detected_at: SystemTime::now(),
            }));
        }

        // Re-hash file
        let hash = self.hash_file(path).await?;
        if hash != baseline.sha256_hash {
            return Ok(Some(FIMViolation {
                path: path.to_path_buf(),
                violation_type: FIMViolationType::HashMismatch,
                expected_hash: Some(baseline.sha256_hash.clone()),
                actual_hash: Some(hash),
                detected_at: SystemTime::now(),
            }));
        }

        // Check size
        let meta = fs::metadata(path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if meta.len() != baseline.size {
            return Ok(Some(FIMViolation {
                path: path.to_path_buf(),
                violation_type: FIMViolationType::SizeChange,
                expected_hash: Some(baseline.sha256_hash.clone()),
                actual_hash: Some(hash),
                detected_at: SystemTime::now(),
            }));
        }

        Ok(None)
    }

    /// Build baseline entry for a single file.
    async fn build_baseline_for_file(&self, path: &Path) -> Result<FileBaseline> {
        let meta = fs::metadata(path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        let hash = self.hash_file(path).await?;

        Ok(FileBaseline {
            path: path.to_path_buf(),
            sha256_hash: hash,
            size: meta.len(),
            modified_time: meta
                .modified()
                .with_context(|| format!("getting mtime for {}", path.display()))?,
            baseline_timestamp: SystemTime::now(),
        })
    }

    /// SHA-256 hash of a file, streaming to avoid large allocations.
    async fn hash_file(&self, path: &Path) -> Result<String> {
        use tokio::io::AsyncReadExt;

        let mut file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("opening {} for hashing", path.display()))?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 8192];

        loop {
            let n = file
                .read(&mut buf)
                .await
                .with_context(|| format!("reading {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Check if path should be excluded based on extension.
    fn is_excluded(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lc = format!(".{}", ext.to_lowercase());
            return self.config.excluded_extensions.contains(&ext_lc);
        }
        false
    }

    /// Take a snapshot clone of baseline map to iterate without holding the mutex.
    fn baseline_snapshot(&self) -> Result<HashMap<PathBuf, FileBaseline>> {
        let guard = self
            .baseline_db
            .lock()
            .map_err(|_| anyhow!("FIM baseline lock poisoned"))?;

        Ok(guard.clone())
    }
}
