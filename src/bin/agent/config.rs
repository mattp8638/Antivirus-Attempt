//! Agent Configuration

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub reporting_interval_secs: u64,
    pub enable_etw: bool,
    pub enable_amsi: bool,
    pub enable_ml_scoring: bool,
    pub enable_threat_intel: bool,
    pub enable_full_scan_on_startup: bool,
    pub quick_scan_paths: Vec<String>,
    pub full_scan_paths: Vec<String>,
    pub max_scan_file_size_mb: u64,
    pub max_scan_findings_per_run: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let quick_scan_paths = if cfg!(target_os = "windows") {
            vec![
                "C:/Users/Public/Downloads".to_string(),
                "C:/Users/Public/Desktop".to_string(),
                "C:/Windows/Temp".to_string(),
                "C:/ProgramData".to_string(),
            ]
        } else {
            vec!["/tmp".to_string(), "/var/tmp".to_string()]
        };

        let full_scan_paths = if cfg!(target_os = "windows") {
            vec![
                "C:/Users".to_string(),
                "C:/ProgramData".to_string(),
                "C:/Windows/Temp".to_string(),
            ]
        } else {
            vec!["/home".to_string(), "/tmp".to_string(), "/var/tmp".to_string()]
        };

        Self {
            api_endpoint: "https://api.tamsilcms.com".to_string(),
            api_key: "your-api-key-here".to_string(),
            reporting_interval_secs: 10,
            enable_etw: true,
            enable_amsi: true,
            enable_ml_scoring: true,
            enable_threat_intel: true,
            enable_full_scan_on_startup: true,
            quick_scan_paths,
            full_scan_paths,
            max_scan_file_size_mb: 50,
            max_scan_findings_per_run: 200,
        }
    }
}

impl AgentConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(contents) = fs::read_to_string(path) {
            let mut config: AgentConfig = serde_json::from_str(&contents)?;
            config.api_endpoint = config.api_endpoint.trim().trim_end_matches('/').to_string();
            config.api_key = config.api_key.trim().to_string();
            Ok(config)
        } else {
            // Create default config
            let config = Self::default();
            let json = serde_json::to_string_pretty(&config)?;
            fs::write(path, json)?;
            Ok(config)
        }
    }
}
