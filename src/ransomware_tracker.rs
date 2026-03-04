use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::models::Alert;

/// Tracks per-process file activity for ransomware behavior patterns
pub struct RansomwareTracker {
    /// Tracks file renames per process: PID -> (old_path, new_path, timestamp)
    process_renames: HashMap<i32, Vec<(String, String, u64)>>,
    /// Tracks file writes per process: PID -> count
    process_writes: HashMap<i32, usize>,
    /// Tracks process start times: PID -> unix timestamp
    process_start_times: HashMap<i32, u64>,
    /// High-value folder access tracking: PID -> accessed_folders
    high_value_folder_access: HashMap<i32, HashSet<PathBuf>>,
    /// Shadow copy deletion detection cache
    shadow_copy_baseline: HashSet<String>,
    /// Last shadow copy check timestamp
    last_shadow_copy_check: u64,
}

impl Default for RansomwareTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RansomwareTracker {
    pub fn new() -> Self {
        Self {
            process_renames: HashMap::new(),
            process_writes: HashMap::new(),
            process_start_times: HashMap::new(),
            high_value_folder_access: HashMap::new(),
            shadow_copy_baseline: HashSet::new(),
            last_shadow_copy_check: 0,
        }
    }

    /// Record a file rename operation by a process
    pub fn track_rename(
        &mut self,
        pid: i32,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
        timestamp: u64,
    ) {
        let renames = self.process_renames.entry(pid).or_default();
        renames.push((old_path.into(), new_path.into(), timestamp));
    }

    /// Record a file write operation by a process
    pub fn track_write(&mut self, pid: i32) {
        *self.process_writes.entry(pid).or_default() += 1;
    }

    /// Register a process start time
    pub fn register_process(&mut self, pid: i32, start_time: u64) {
        self.process_start_times.insert(pid, start_time);
    }

    /// Track access to high-value folders (user dirs, network shares, etc.)
    pub fn track_folder_access(&mut self, pid: i32, folder: PathBuf) {
        self.high_value_folder_access
            .entry(pid)
            .or_default()
            .insert(folder);
    }

    /// Detect rapid rename/encrypt patterns indicative of ransomware
    /// Returns alerts for processes showing ransomware-like behavior
    pub fn detect_rename_encrypt_pattern(
        &mut self,
        rename_threshold: usize,
        time_window_seconds: u64,
        current_ts: u64,
        suspicious_extensions: &HashSet<String>,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let cutoff = current_ts.saturating_sub(time_window_seconds);

        // Clean up old entries
        for renames in self.process_renames.values_mut() {
            renames.retain(|(_, _, ts)| *ts >= cutoff);
        }

        for (pid, renames) in &self.process_renames {
            if renames.len() < rename_threshold {
                continue;
            }

            let recent_renames: Vec<_> = renames.iter().filter(|(_, _, ts)| *ts >= cutoff).collect();

            if recent_renames.len() < rename_threshold {
                continue;
            }

            // Check for extension changes to suspicious extensions
            let mut suspicious_ext_count = 0;
            let mut sample_paths = Vec::new();

            for (old_path, new_path, _) in recent_renames.iter().take(5) {
                let old_ext = extract_extension(old_path);
                let new_ext = extract_extension(new_path);

                if old_ext != new_ext && suspicious_extensions.contains(&new_ext) {
                    suspicious_ext_count += 1;
                    sample_paths.push(format!("{} -> {}", old_path, new_path));
                }
            }

            if suspicious_ext_count > 0 || recent_renames.len() >= rename_threshold * 2 {
                let severity = if suspicious_ext_count > 0 {
                    "high"
                } else {
                    "medium"
                };

                let write_count = self.process_writes.get(pid).copied().unwrap_or(0);
                let process_age = self
                    .process_start_times
                    .get(pid)
                    .map(|start| current_ts.saturating_sub(*start))
                    .unwrap_or(0);

                let message = format!(
                    "Ransomware-like file rename pattern detected: PID {} performed {} renames ({} to suspicious extensions) in {}s (process age: {}s, {} writes)",
                    pid,
                    recent_renames.len(),
                    suspicious_ext_count,
                    time_window_seconds,
                    process_age,
                    write_count
                );

                let mut alert = Alert::with_pid("per_process_rename_encrypt_pattern", severity, message, *pid);

                if !sample_paths.is_empty() {
                    alert.set_details(serde_json::json!({
                        "rename_count": recent_renames.len(),
                        "suspicious_ext_count": suspicious_ext_count,
                        "sample_renames": sample_paths,
                        "time_window_seconds": time_window_seconds,
                        "write_count": write_count,
                        "process_age_seconds": process_age,
                    }));
                }

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Detect mass access to high-value folders (user dirs, network shares)
    pub fn detect_mass_folder_access(
        &mut self,
        folder_access_threshold: usize,
        high_value_patterns: &[&str],
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for (pid, accessed_folders) in &self.high_value_folder_access {
            let high_value_count = accessed_folders
                .iter()
                .filter(|folder| is_high_value_folder(folder, high_value_patterns))
                .count();

            if high_value_count >= folder_access_threshold {
                let sample_folders: Vec<String> = accessed_folders
                    .iter()
                    .filter(|f| is_high_value_folder(f, high_value_patterns))
                    .take(5)
                    .map(|p| p.display().to_string())
                    .collect();

                let message = format!(
                    "Mass high-value folder access detected: PID {} accessed {} high-value folders",
                    pid, high_value_count
                );

                let mut alert = Alert::with_pid(
                    "mass_high_value_folder_access",
                    "high",
                    message,
                    *pid,
                );

                alert.set_details(serde_json::json!({
                    "high_value_folder_count": high_value_count,
                    "total_accessed_folders": accessed_folders.len(),
                    "sample_folders": sample_folders,
                }));

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Detect Windows shadow copy deletion (critical ransomware indicator)
    /// Checks for vssadmin delete operations and shadow copy baseline changes
    pub fn detect_shadow_copy_deletion(
        &mut self,
        check_interval_seconds: u64,
        current_ts: u64,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Rate-limit shadow copy checks (expensive operation)
        if current_ts.saturating_sub(self.last_shadow_copy_check) < check_interval_seconds {
            return alerts;
        }

        self.last_shadow_copy_check = current_ts;

        // Windows-specific: Check for shadow copies
        #[cfg(target_os = "windows")]
        {
            match enumerate_shadow_copies() {
                Ok(current_copies) => {
                    if !self.shadow_copy_baseline.is_empty() {
                        let deleted: Vec<_> = self
                            .shadow_copy_baseline
                            .difference(&current_copies)
                            .collect();

                        if !deleted.is_empty() {
                            let message = format!(
                                "Shadow copy deletion detected: {} shadow copies removed (baseline: {}, current: {})",
                                deleted.len(),
                                self.shadow_copy_baseline.len(),
                                current_copies.len()
                            );

                            let mut alert = Alert::new("shadow_copy_deletion_detected", "critical", message);

                            let deleted_ids: Vec<String> =
                                deleted.iter().take(5).map(|s| (*s).clone()).collect();

                            alert.set_details(serde_json::json!({
                                "deleted_count": deleted.len(),
                                "deleted_ids": deleted_ids,
                                "baseline_count": self.shadow_copy_baseline.len(),
                                "current_count": current_copies.len(),
                            }));

                            alerts.push(alert);
                        }
                    }

                    // Update baseline
                    self.shadow_copy_baseline = current_copies;
                }
                Err(e) => {
                    alerts.push(Alert::new(
                        "shadow_copy_enumeration_failed",
                        "medium",
                        format!("Shadow copy enumeration failed: {}", e),
                    ));
                }
            }
        }

        alerts
    }

    /// Cleanup old process tracking data to prevent memory growth
    pub fn cleanup_stale_processes(
        &mut self,
        current_ts: u64,
        process_timeout_seconds: u64,
    ) {
        let cutoff = current_ts.saturating_sub(process_timeout_seconds);

        self.process_start_times
            .retain(|_, start_time| *start_time >= cutoff);

        let active_pids: HashSet<i32> = self.process_start_times.keys().copied().collect();

        self.process_renames
            .retain(|pid, _| active_pids.contains(pid));
        self.process_writes
            .retain(|pid, _| active_pids.contains(pid));
        self.high_value_folder_access
            .retain(|pid, _| active_pids.contains(pid));
    }
}

/// Extract file extension from path
fn extract_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

/// Check if folder matches high-value patterns
fn is_high_value_folder(folder: &Path, patterns: &[&str]) -> bool {
    let folder_str = folder.to_string_lossy().to_lowercase();

    for pattern in patterns {
        if folder_str.contains(&pattern.to_lowercase()) {
            return true;
        }
    }

    false
}

/// Enumerate Windows shadow copies using vssadmin
#[cfg(target_os = "windows")]
fn enumerate_shadow_copies() -> Result<HashSet<String>, String> {
    let output = Command::new("vssadmin")
        .args(["list", "shadows"])
        .output()
        .map_err(|e| format!("vssadmin failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "vssadmin returned non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut copies = HashSet::new();

    for line in stdout.lines() {
        if line.trim().starts_with("Shadow Copy ID:") {
            if let Some(id) = line.split(':').nth(1) {
                copies.insert(id.trim().to_string());
            }
        }
    }

    Ok(copies)
}

#[cfg(not(target_os = "windows"))]
fn enumerate_shadow_copies() -> Result<HashSet<String>, String> {
    // Not applicable on non-Windows platforms
    Ok(HashSet::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_per_process_renames() {
        let mut tracker = RansomwareTracker::new();
        tracker.register_process(100, 1000);
        tracker.track_rename(100, "file.txt", "file.locked", 1010);
        tracker.track_rename(100, "doc.pdf", "doc.encrypted", 1020);

        let mut exts = HashSet::new();
        exts.insert(".locked".to_string());
        exts.insert(".encrypted".to_string());

        let alerts = tracker.detect_rename_encrypt_pattern(2, 300, 1030, &exts);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "high");
        assert!(alerts[0].message.contains("Ransomware-like"));
    }

    #[test]
    fn detects_mass_folder_access() {
        let mut tracker = RansomwareTracker::new();
        tracker.register_process(200, 2000);

        tracker.track_folder_access(200, PathBuf::from("C:\\Users\\Alice\\Documents"));
        tracker.track_folder_access(200, PathBuf::from("C:\\Users\\Bob\\Documents"));
        tracker.track_folder_access(200, PathBuf::from("\\\\server\\share"));

        let patterns = vec!["users", "documents", "\\\\\\"]; // Network share pattern
        let alerts = tracker.detect_mass_folder_access(2, &patterns);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "high");
        assert!(alerts[0].message.contains("Mass high-value folder access"));
    }

    #[test]
    fn cleanup_removes_stale_processes() {
        let mut tracker = RansomwareTracker::new();
        tracker.register_process(300, 1000);
        tracker.register_process(301, 5000);
        tracker.track_write(300);
        tracker.track_write(301);

        tracker.cleanup_stale_processes(6000, 3600);

        assert!(!tracker.process_writes.contains_key(&300));
        assert!(tracker.process_writes.contains_key(&301));
    }

    #[test]
    fn extract_extension_works() {
        assert_eq!(extract_extension("file.txt"), ".txt");
        assert_eq!(extract_extension("doc.LOCKED"), ".locked");
        assert_eq!(extract_extension("noext"), "");
    }

    #[test]
    fn high_value_folder_detection() {
        let patterns = vec!["documents", "desktop", "\\\\\\server"];

        assert!(is_high_value_folder(
            &PathBuf::from("C:\\Users\\Alice\\Documents"),
            &patterns
        ));
        assert!(is_high_value_folder(
            &PathBuf::from("\\\\fileserver\\share"),
            &patterns
        ));
        assert!(!is_high_value_folder(
            &PathBuf::from("C:\\Temp"),
            &patterns
        ));
    }
}
