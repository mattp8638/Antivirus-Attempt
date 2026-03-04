//! YARA Scanner Module
//! File scanning with YARA rules for malware detection

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use log::{info, warn, error, debug};

#[cfg(feature = "embedded-yara")]
use yara::{Compiler, Rules};

/// YARA rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub rule_id: String,
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub severity: String,
    pub tags: Vec<String>,
    pub created_at: SystemTime,
}

/// YARA scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub file_path: String,
    pub matched_rules: Vec<YaraMatch>,
    pub scan_duration_ms: u64,
    pub error: Option<String>,
}

/// Individual YARA rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
}

/// Matched string from YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub matches: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// YARA scanner configuration
#[derive(Debug, Clone)]
pub struct YaraScannerConfig {
    pub rules_directory: PathBuf,
    pub max_file_size: u64,
    pub timeout_seconds: u64,
    pub scan_archives: bool,
    pub follow_symlinks: bool,
}

impl Default for YaraScannerConfig {
    fn default() -> Self {
        Self {
            rules_directory: PathBuf::from("/var/tamsilcms/yara/rules"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            timeout_seconds: 30,
            scan_archives: false,
            follow_symlinks: false,
        }
    }
}

/// YARA scanner
pub struct YaraScanner {
    config: YaraScannerConfig,
    rules: Vec<YaraRule>,
    rule_files: Vec<PathBuf>,
    merged_rules_path: Option<PathBuf>,
    #[cfg(feature = "embedded-yara")]
    embedded_rules: Option<Rules>,
    rules_compiled: bool,
}

impl YaraScanner {
    /// Create new YARA scanner
    pub fn new(config: YaraScannerConfig) -> Result<Self> {
        // Create rules directory if it doesn't exist
        if !config.rules_directory.exists() {
            fs::create_dir_all(&config.rules_directory)
                .context("Failed to create YARA rules directory")?;
        }
        
        info!("YARA scanner initialized with rules directory: {:?}", config.rules_directory);
        
        Ok(Self {
            config,
            rules: Vec::new(),
            rule_files: Vec::new(),
            merged_rules_path: None,
            #[cfg(feature = "embedded-yara")]
            embedded_rules: None,
            rules_compiled: false,
        })
    }
    
    /// Load YARA rules from directory
    pub fn load_rules(&mut self) -> Result<usize> {
        self.rules.clear();
        self.rule_files.clear();
        self.merged_rules_path = None;
        #[cfg(feature = "embedded-yara")]
        {
            self.embedded_rules = None;
        }
        
        if !self.config.rules_directory.exists() {
            warn!("YARA rules directory does not exist: {:?}", self.config.rules_directory);
            return Ok(0);
        }
        
        // Scan for .yar and .yara files
        let rule_files = self.find_rule_files(&self.config.rules_directory)?;
        self.rule_files = rule_files.clone();
        
        for rule_file in rule_files {
            match self.load_rule_file(&rule_file) {
                Ok(rule) => {
                    debug!("Loaded YARA rule: {} from {:?}", rule.name, rule_file);
                    self.rules.push(rule);
                }
                Err(e) => {
                    error!("Failed to load YARA rule from {:?}: {}", rule_file, e);
                }
            }
        }
        
        info!("Loaded {} YARA rules", self.rules.len());
        self.rules_compiled = self.rules.len() > 0;

        if self.rules_compiled {
            self.merged_rules_path = Some(self.write_merged_rules_file(&rule_files)?);

            #[cfg(feature = "embedded-yara")]
            {
                match self.compile_embedded_rules(&rule_files) {
                    Ok(compiled) => {
                        self.embedded_rules = Some(compiled);
                        info!("Embedded YARA backend initialized successfully");
                    }
                    Err(err) => {
                        warn!(
                            "Embedded YARA compilation failed; CLI fallback will be used: {}",
                            err
                        );
                    }
                }
            }
        }
        
        Ok(self.rules.len())
    }

    fn write_merged_rules_file(&self, rule_files: &[PathBuf]) -> Result<PathBuf> {
        let merged_path = self.config.rules_directory.join(".tamsilcms_merged_rules.yar");
        let mut merged_content = String::new();

        for path in rule_files {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read YARA rule file {:?}", path))?;
            merged_content.push_str(&content);
            merged_content.push('\n');
        }

        fs::write(&merged_path, merged_content)
            .with_context(|| format!("Failed to write merged YARA rules to {:?}", merged_path))?;

        Ok(merged_path)
    }

    #[cfg(feature = "embedded-yara")]
    fn compile_embedded_rules(&self, rule_files: &[PathBuf]) -> Result<Rules> {
        let mut compiler = Compiler::new()?;
        for path in rule_files {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read YARA rule file {:?}", path))?;
            compiler = compiler
                .add_rules_str(&content)
                .with_context(|| format!("Failed to compile YARA rules from {:?}", path))?;
        }
        Ok(compiler.compile_rules()?)
    }
    
    /// Find all YARA rule files recursively
    fn find_rule_files(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut rule_files = Vec::new();
        
        if !dir.is_dir() {
            return Ok(rule_files);
        }
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                // Recursive scan
                rule_files.extend(self.find_rule_files(&path)?);
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        rule_files.push(path);
                    }
                }
            }
        }
        
        Ok(rule_files)
    }
    
    /// Load a single YARA rule file
    fn load_rule_file(&self, path: &Path) -> Result<YaraRule> {
        let content = fs::read_to_string(path)
            .context("Failed to read YARA rule file")?;
        
        // Parse rule metadata from content
        let rule_id = self.extract_rule_id(&content);
        let name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        let description = self.extract_metadata(&content, "description");
        let author = self.extract_metadata(&content, "author");
        let severity = self.extract_metadata(&content, "severity")
            .unwrap_or_else(|| "medium".to_string());
        
        let tags = self.extract_tags(&content);
        
        Ok(YaraRule {
            rule_id,
            name,
            description,
            author,
            severity,
            tags,
            created_at: SystemTime::now(),
        })
    }
    
    /// Extract rule ID from YARA rule content
    fn extract_rule_id(&self, content: &str) -> String {
        // Look for: rule <rule_name>
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rule ") {
                if let Some(name) = trimmed.split_whitespace().nth(1) {
                    return name.trim_end_matches('{').trim().to_string();
                }
            }
        }
        format!("rule_{}", uuid::Uuid::new_v4())
    }
    
    /// Extract metadata field from YARA rule
    fn extract_metadata(&self, content: &str, field: &str) -> Option<String> {
        let search_str = format!("{}=", field);
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains(&search_str) {
                if let Some(value) = trimmed.split('=').nth(1) {
                    return Some(value.trim().trim_matches('"').to_string());
                }
            }
        }
        None
    }
    
    /// Extract tags from YARA rule
    fn extract_tags(&self, content: &str) -> Vec<String> {
        let mut tags = Vec::new();
        
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("rule ") && trimmed.contains(':') {
                // Format: rule rulename : tag1 tag2 {
                if let Some(tags_part) = trimmed.split(':').nth(1) {
                    let tags_str = tags_part.split('{').next().unwrap_or("");
                    tags.extend(tags_str.split_whitespace().map(|s| s.to_string()));
                }
            }
        }
        
        tags
    }
    
    /// Scan a file with YARA rules
    pub fn scan_file(&self, file_path: &Path) -> Result<YaraScanResult> {
        let start = SystemTime::now();
        
        // Check file size
        let metadata = fs::metadata(file_path)
            .context("Failed to get file metadata")?;
        
        if metadata.len() > self.config.max_file_size {
            return Ok(YaraScanResult {
                file_path: file_path.to_string_lossy().to_string(),
                matched_rules: Vec::new(),
                scan_duration_ms: 0,
                error: Some(format!("File too large: {} bytes", metadata.len())),
            });
        }
        
        if !self.rules_compiled {
            return Ok(YaraScanResult {
                file_path: file_path.to_string_lossy().to_string(),
                matched_rules: Vec::new(),
                scan_duration_ms: 0,
                error: Some("No YARA rules loaded".to_string()),
            });
        }
        
        // Perform scan (placeholder - would use yara-rust crate in production)
        let matched_rules = self.perform_scan(file_path)?;
        
        let duration = SystemTime::now()
            .duration_since(start)
            .unwrap_or_default()
            .as_millis() as u64;
        
        Ok(YaraScanResult {
            file_path: file_path.to_string_lossy().to_string(),
            matched_rules,
            scan_duration_ms: duration,
            error: None,
        })
    }
    
    /// Perform actual YARA scan
    fn perform_scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        if self.rule_files.is_empty() {
            return Ok(Vec::new());
        }

        let metadata_by_name: HashMap<&str, &YaraRule> = self
            .rules
            .iter()
            .map(|rule| (rule.rule_id.as_str(), rule))
            .collect();

        let mut matched_rules = Vec::new();

        #[cfg(feature = "embedded-yara")]
        {
            if let Some(rules) = &self.embedded_rules {
                let scan_results = rules.scan_file(file_path, self.config.timeout_seconds as i32)?;
                for rule in scan_results.iter() {
                    let rule_name = rule.identifier.to_string();
                    let (tags, meta) = self.lookup_metadata(&metadata_by_name, &rule_name);
                    matched_rules.push(YaraMatch {
                        rule_name,
                        namespace: None,
                        tags,
                        meta,
                        strings: Vec::new(),
                    });
                }
                return Ok(matched_rules);
            }
        }

        let merged_rules_path = self
            .merged_rules_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Merged YARA rules file is not initialized"))?;

        let output = Command::new("yara")
            .arg(merged_rules_path.to_string_lossy().to_string())
            .arg(file_path.to_string_lossy().to_string())
            .output()
            .map_err(|err| anyhow::anyhow!("Failed to execute yara CLI (is it installed?): {}", err))?;

        let status = output.status.code().unwrap_or_default();
        if !output.status.success() && status != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(anyhow::anyhow!("yara scan failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
            let mut parts = line.split_whitespace();
            let rule_name = parts.next().unwrap_or("unknown").to_string();
            let (tags, meta) = self.lookup_metadata(&metadata_by_name, &rule_name);
            matched_rules.push(YaraMatch {
                rule_name,
                namespace: None,
                tags,
                meta,
                strings: Vec::new(),
            });
        }

        Ok(matched_rules)
    }

    fn lookup_metadata(
        &self,
        metadata_by_name: &HashMap<&str, &YaraRule>,
        rule_name: &str,
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut meta = HashMap::new();
        let mut tags = Vec::new();

        if let Some(rule_meta) = metadata_by_name.get(rule_name) {
            meta.insert("severity".to_string(), rule_meta.severity.clone());
            if let Some(description) = &rule_meta.description {
                meta.insert("description".to_string(), description.clone());
            }
            if let Some(author) = &rule_meta.author {
                meta.insert("author".to_string(), author.clone());
            }
            tags = rule_meta.tags.clone();
        }

        (tags, meta)
    }
    
    /// Scan directory recursively
    pub fn scan_directory(&self, dir_path: &Path) -> Result<Vec<YaraScanResult>> {
        let mut results = Vec::new();
        
        if !dir_path.is_dir() {
            return Err(anyhow::anyhow!("Path is not a directory"));
        }
        
        self.scan_directory_recursive(dir_path, &mut results)?;
        
        Ok(results)
    }
    
    /// Recursive directory scan helper
    fn scan_directory_recursive(
        &self,
        dir: &Path,
        results: &mut Vec<YaraScanResult>,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                self.scan_directory_recursive(&path, results)?;
            } else if path.is_file() {
                match self.scan_file(&path) {
                    Ok(result) => {
                        if !result.matched_rules.is_empty() || result.error.is_some() {
                            results.push(result);
                        }
                    }
                    Err(e) => {
                        error!("Failed to scan file {:?}: {}", path, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get loaded rules count
    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }
    
    /// Get rule by name
    pub fn get_rule(&self, name: &str) -> Option<&YaraRule> {
        self.rules.iter().find(|r| r.name == name)
    }
    
    /// Check if scanner is ready
    pub fn is_ready(&self) -> bool {
        self.rules_compiled && !self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;
    
    #[test]
    fn creates_scanner() {
        let config = YaraScannerConfig::default();
        let scanner = YaraScanner::new(config);
        assert!(scanner.is_ok());
    }
    
    #[test]
    fn loads_rules_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        
        // Create sample YARA rule
        let rule_content = r#"
rule TestMalware : malware trojan
{
    meta:
        description = "Test malware rule"
        author = "TamsilCMS"
        severity = "high"
    
    strings:
        $str1 = "malicious"
        $str2 = { 6D 61 6C }
    
    condition:
        any of them
}
"#;
        
        let rule_file = rules_dir.join("test_malware.yar");
        let mut file = File::create(&rule_file).unwrap();
        file.write_all(rule_content.as_bytes()).unwrap();
        
        let config = YaraScannerConfig {
            rules_directory: rules_dir,
            ..Default::default()
        };
        
        let mut scanner = YaraScanner::new(config).unwrap();
        let count = scanner.load_rules().unwrap();
        
        assert_eq!(count, 1);
        assert!(scanner.is_ready());
    }
    
    #[test]
    fn extracts_rule_metadata() {
        let config = YaraScannerConfig::default();
        let scanner = YaraScanner::new(config).unwrap();
        
        let content = r#"
rule TestRule
{
    meta:
        description = "Test description"
        author = "Test Author"
        severity = "critical"
    
    condition:
        true
}
"#;
        
        let desc = scanner.extract_metadata(content, "description");
        assert_eq!(desc, Some("Test description".to_string()));
        
        let author = scanner.extract_metadata(content, "author");
        assert_eq!(author, Some("Test Author".to_string()));
    }
    
    #[test]
    fn extracts_tags() {
        let config = YaraScannerConfig::default();
        let scanner = YaraScanner::new(config).unwrap();
        
        let content = "rule TestRule : malware trojan windows {";
        let tags = scanner.extract_tags(content);
        
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&"malware".to_string()));
        assert!(tags.contains(&"trojan".to_string()));
        assert!(tags.contains(&"windows".to_string()));
    }
}
