use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct IocConfig {
    pub blocked_process_names: HashSet<String>,
    pub blocked_command_substrings: HashSet<String>,
    pub blocked_remote_ips: HashSet<String>,
    pub blocked_remote_ports: HashSet<u16>,
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub scan_interval_seconds: u64,
    pub alert_log_path: PathBuf,
    pub state_path: PathBuf,
    pub monitored_directories: Vec<PathBuf>,
    pub excluded_directory_names: HashSet<String>,
    pub excluded_file_names: HashSet<String>,
    pub ioc: IocConfig,
    pub run_once: bool,
    pub initialize_baseline_without_alerting: bool,
    pub cpp_collector_path: PathBuf,
    pub auto_kill_on_high: bool,
    pub response_profile: ResponseProfile,
    pub response_action_cooldown_seconds: u64,
    pub response_allowlisted_process_names: HashSet<String>,
    pub response_allowlisted_process_paths: HashSet<String>,
    pub incident_log_path: PathBuf,
    pub incident_risk_threshold: u32,
    pub telemetry_enabled: bool,
    pub telemetry_endpoint: String,
    pub telemetry_api_key: String,
    pub telemetry_spool_path: PathBuf,
    pub telemetry_tenant_id: String,
    pub telemetry_endpoint_id: String,
    pub heartbeat_log_path: PathBuf,
    pub ui_status_path: PathBuf,
    pub ui_command_path: PathBuf,
    pub policy_path: PathBuf,
    pub enable_policy_reload: bool,
    pub suspicious_file_extensions: HashSet<String>,
    pub quarantine_dir: PathBuf,
    pub auto_quarantine_suspicious_files: bool,
    pub auto_quarantine_yara_matches: bool,
    pub ransomware_change_threshold: usize,
    pub ransomware_delete_threshold: usize,
    pub ransomware_extension_threshold: usize,
    pub ransomware_note_threshold: usize,
    pub ransomware_note_sample_limit: usize,
    pub ransomware_note_tokens: HashSet<String>,
    pub ransomware_alert_cooldown_seconds: u64,
    pub ransomware_sample_limit: usize,
    pub yara_rules_url: String,
    pub yara_rules_path: PathBuf,
    pub yara_poll_interval_seconds: u64,
    pub yara_scan_limit: usize,
    pub yara_max_file_size_bytes: u64,
    pub yara_match_cooldown_seconds: u64,
    pub yara_scan_only_suspicious_ext: bool,
    pub kernel_ingestion_enabled: bool,
    pub kernel_ingestion_keywords: Vec<String>,
    pub kernel_event_limit: usize,
    pub kernel_use_audit_search: bool,
    pub kernel_event_log_path: PathBuf,
    pub kernel_dedupe_window_seconds: u64,
    pub windows_ingestion_enabled: bool,
    pub windows_event_channels: Vec<String>,
    pub windows_event_ids: Vec<u32>,
    pub windows_event_limit: usize,
    pub windows_event_log_path: PathBuf,
    pub windows_dedupe_window_seconds: u64,
    pub fim_enabled: bool,
    pub fim_scan_interval_seconds: u64,
    pub fim_monitored_paths: Vec<PathBuf>,
    pub fim_excluded_extensions: HashSet<String>,
    pub fim_baseline_path: PathBuf,
    pub memory_ingestion_enabled: bool,
    pub memory_event_log_path: PathBuf,
    pub memory_event_limit: usize,
    pub memory_dedupe_window_seconds: u64,
    pub backend_enabled: bool,
    pub backend_url: String,
    pub backend_endpoint_id: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseProfile {
    DetectOnly,
    Contain,
    Aggressive,
}

impl ResponseProfile {
    pub fn allows_containment(self) -> bool {
        matches!(self, Self::Contain | Self::Aggressive)
    }

    pub fn allows_aggressive(self) -> bool {
        matches!(self, Self::Aggressive)
    }
}

impl AgentConfig {
    pub fn load() -> Result<Self, anyhow::Error> {
        let mut config = Self::default();

        let env_path = env::var("TAMSILCMS_CONFIG").ok().map(PathBuf::from);
        let selected_path = if let Some(path) = env_path {
            if !path.exists() {
                return Err(anyhow::anyhow!(
                    "TAMSILCMS_CONFIG points to missing file: {}",
                    path.display()
                ));
            }
            Some(path)
        } else {
            [
                PathBuf::from("config/edr_config.json"),
                PathBuf::from("edr_config.json"),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
        };

        if let Some(path) = selected_path {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file {}", path.display()))?;
            let root: Value = serde_json::from_str(&content)
                .with_context(|| format!("Invalid JSON in config file {}", path.display()))?;
            Self::apply_json_overrides(&mut config, &root);
        }

        Ok(config)
    }

    fn apply_json_overrides(config: &mut Self, root: &Value) {
        if let Some(value) = root.get("auto_kill_on_high").and_then(Value::as_bool) {
            config.auto_kill_on_high = value;
        }

        if let Some(value) = root.get("ui_status_path").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                config.ui_status_path = PathBuf::from(trimmed);
            }
        }

        if let Some(value) = root.get("ui_command_path").and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                config.ui_command_path = PathBuf::from(trimmed);
            }
        }

        if let Some(value) = root
            .get("auto_quarantine_suspicious_files")
            .and_then(Value::as_bool)
        {
            config.auto_quarantine_suspicious_files = value;
        }

        if let Some(value) = root.get("response_profile") {
            if let Some(profile) = Self::parse_response_profile(value) {
                config.response_profile = profile;
            }
        }

        if let Some(value) = root
            .get("response_action_cooldown_seconds")
            .and_then(Value::as_u64)
        {
            if value > 0 {
                config.response_action_cooldown_seconds = value;
            }
        }

        if let Some(value) = root.get("response_allowlisted_process_names") {
            let parsed = Self::parse_string_set(value);
            if !parsed.is_empty() {
                config.response_allowlisted_process_names = parsed;
            }
        }

        if let Some(value) = root.get("response_allowlisted_process_paths") {
            let parsed = Self::parse_string_set(value);
            if !parsed.is_empty() {
                config.response_allowlisted_process_paths = parsed;
            }
        }

        if let Some(response) = root.get("response") {
            if let Some(value) = response.get("profile") {
                if let Some(profile) = Self::parse_response_profile(value) {
                    config.response_profile = profile;
                }
            }

            if let Some(value) = response.get("cooldown_seconds").and_then(Value::as_u64) {
                if value > 0 {
                    config.response_action_cooldown_seconds = value;
                }
            }

            if let Some(value) = response.get("allowlisted_process_names") {
                let parsed = Self::parse_string_set(value);
                if !parsed.is_empty() {
                    config.response_allowlisted_process_names = parsed;
                }
            }

            if let Some(value) = response.get("allowlisted_process_paths") {
                let parsed = Self::parse_string_set(value);
                if !parsed.is_empty() {
                    config.response_allowlisted_process_paths = parsed;
                }
            }
        }
    }

    fn parse_response_profile(value: &Value) -> Option<ResponseProfile> {
        let normalized = value.as_str()?.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "detect_only" | "detect-only" | "detect" => Some(ResponseProfile::DetectOnly),
            "contain" | "containment" => Some(ResponseProfile::Contain),
            "aggressive" => Some(ResponseProfile::Aggressive),
            _ => None,
        }
    }

    fn parse_string_set(value: &Value) -> HashSet<String> {
        value
            .as_array()
            .into_iter()
            .flat_map(|items| items.iter())
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| item.to_ascii_lowercase())
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.scan_interval_seconds < 1 {
            return Err("scan_interval_seconds must be >= 1".into());
        }
        if self.monitored_directories.is_empty() {
            return Err("monitored_directories cannot be empty".into());
        }
        if self.incident_risk_threshold == 0 {
            return Err("incident_risk_threshold must be >= 1".into());
        }
        if self.response_action_cooldown_seconds < 1 {
            return Err("response_action_cooldown_seconds must be >= 1".into());
        }
        if self.telemetry_enabled && self.telemetry_endpoint.trim().is_empty() {
            return Err("telemetry endpoint required when telemetry is enabled".into());
        }
        if self.telemetry_enabled && self.telemetry_tenant_id.trim().is_empty() {
            return Err("telemetry tenant_id required when telemetry is enabled".into());
        }
        if self.telemetry_enabled && self.telemetry_endpoint_id.trim().is_empty() {
            return Err("telemetry endpoint_id required when telemetry is enabled".into());
        }
        if self.kernel_ingestion_enabled && self.kernel_ingestion_keywords.is_empty() {
            return Err("kernel ingestion keywords must be non-empty when enabled".into());
        }
        if self.ransomware_change_threshold < 1 {
            return Err("ransomware_change_threshold must be >= 1".into());
        }
        if self.ransomware_delete_threshold < 1 {
            return Err("ransomware_delete_threshold must be >= 1".into());
        }
        if self.ransomware_extension_threshold < 1 {
            return Err("ransomware_extension_threshold must be >= 1".into());
        }
        if self.ransomware_note_threshold < 1 {
            return Err("ransomware_note_threshold must be >= 1".into());
        }
        if self.ransomware_note_sample_limit < 1 {
            return Err("ransomware_note_sample_limit must be >= 1".into());
        }
        if self.ransomware_alert_cooldown_seconds < 1 {
            return Err("ransomware_alert_cooldown_seconds must be >= 1".into());
        }
        if self.ransomware_sample_limit < 1 {
            return Err("ransomware_sample_limit must be >= 1".into());
        }
        if self.yara_poll_interval_seconds < 1 {
            return Err("yara_poll_interval_seconds must be >= 1".into());
        }
        if self.yara_scan_limit < 1 {
            return Err("yara_scan_limit must be >= 1".into());
        }
        if self.yara_max_file_size_bytes < 1 {
            return Err("yara_max_file_size_bytes must be >= 1".into());
        }
        if self.yara_match_cooldown_seconds < 1 {
            return Err("yara_match_cooldown_seconds must be >= 1".into());
        }
        if self.kernel_dedupe_window_seconds < 1 {
            return Err("kernel_dedupe_window_seconds must be >= 1".into());
        }
        if self.windows_ingestion_enabled && self.windows_event_channels.is_empty() {
            return Err("windows_event_channels must be non-empty when enabled".into());
        }
        if self.windows_event_limit < 1 {
            return Err("windows_event_limit must be >= 1".into());
        }
        if self.windows_dedupe_window_seconds < 1 {
            return Err("windows_dedupe_window_seconds must be >= 1".into());
        }
        if self.fim_enabled && self.fim_scan_interval_seconds < 1 {
            return Err("fim_scan_interval_seconds must be >= 1".into());
        }
        if self.fim_enabled && self.fim_monitored_paths.is_empty() {
            return Err("fim_monitored_paths cannot be empty when FIM is enabled".into());
        }
        if self.memory_ingestion_enabled && self.memory_event_limit < 1 {
            return Err("memory_event_limit must be >= 1".into());
        }
        if self.memory_ingestion_enabled && self.memory_dedupe_window_seconds < 1 {
            return Err("memory_dedupe_window_seconds must be >= 1".into());
        }
        if self.backend_enabled && self.backend_url.trim().is_empty() {
            return Err("backend_url must be set when backend is enabled".into());
        }
        if self.backend_enabled && self.backend_endpoint_id <= 0 {
            return Err("backend_endpoint_id must be > 0 when backend is enabled".into());
        }
        Ok(())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 30,
            alert_log_path: PathBuf::from("alerts.log"),
            state_path: PathBuf::from("state.db"),
            monitored_directories: vec![PathBuf::from(".")],
            excluded_directory_names: HashSet::new(),
            excluded_file_names: HashSet::new(),
            ioc: IocConfig {
                blocked_process_names: HashSet::new(),
                blocked_command_substrings: HashSet::new(),
                blocked_remote_ips: HashSet::new(),
                blocked_remote_ports: HashSet::new(),
            },
            run_once: false,
            initialize_baseline_without_alerting: true,
            cpp_collector_path: PathBuf::from("./process_collector"),
            auto_kill_on_high: false,
            response_profile: ResponseProfile::DetectOnly,
            response_action_cooldown_seconds: 300,
            response_allowlisted_process_names: HashSet::new(),
            response_allowlisted_process_paths: HashSet::new(),
            incident_log_path: PathBuf::from("incidents.jsonl"),
            incident_risk_threshold: 10,
            telemetry_enabled: false,
            telemetry_endpoint: String::new(),
            telemetry_api_key: String::new(),
            telemetry_spool_path: PathBuf::from("telemetry_spool.jsonl"),
            telemetry_tenant_id: String::new(),
            telemetry_endpoint_id: String::new(),
            heartbeat_log_path: PathBuf::from("heartbeat.jsonl"),
            ui_status_path: PathBuf::from("agent_status.json"),
            ui_command_path: PathBuf::from("agent_command.json"),
            policy_path: PathBuf::from("policy.conf"),
            enable_policy_reload: false,
            suspicious_file_extensions: HashSet::new(),
            quarantine_dir: PathBuf::from("quarantine"),
            auto_quarantine_suspicious_files: false,
            auto_quarantine_yara_matches: false,
            ransomware_change_threshold: 50,
            ransomware_delete_threshold: 20,
            ransomware_extension_threshold: 5,
            ransomware_note_threshold: 1,
            ransomware_note_sample_limit: 3,
            ransomware_note_tokens: HashSet::new(),
            ransomware_alert_cooldown_seconds: 300,
            ransomware_sample_limit: 5,
            yara_rules_url: String::new(),
            yara_rules_path: PathBuf::from("yara_rules.yar"),
            yara_poll_interval_seconds: 3600,
            yara_scan_limit: 50,
            yara_max_file_size_bytes: 10 * 1024 * 1024,
            yara_match_cooldown_seconds: 300,
            yara_scan_only_suspicious_ext: false,
            kernel_ingestion_enabled: false,
            kernel_ingestion_keywords: vec!["panic".to_string()],
            kernel_event_limit: 100,
            kernel_use_audit_search: false,
            kernel_event_log_path: PathBuf::from("kernel_events.jsonl"),
            kernel_dedupe_window_seconds: 300,
            windows_ingestion_enabled: false,
            windows_event_channels: Vec::new(),
            windows_event_ids: Vec::new(),
            windows_event_limit: 100,
            windows_event_log_path: PathBuf::from("windows_events.jsonl"),
            windows_dedupe_window_seconds: 300,
            fim_enabled: false,
            fim_scan_interval_seconds: 300,
            fim_monitored_paths: vec![PathBuf::from(".")],
            fim_excluded_extensions: HashSet::new(),
            fim_baseline_path: PathBuf::from("fim_baseline.tsv"),
            memory_ingestion_enabled: false,
            memory_event_log_path: PathBuf::from("memory_events.jsonl"),
            memory_event_limit: 100,
            memory_dedupe_window_seconds: 300,
            backend_enabled: false,
            backend_url: String::new(),
            backend_endpoint_id: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_response_overrides() {
        let mut config = AgentConfig::default();
        let payload = serde_json::json!({
            "ui_status_path": "state/endpoint_ui_status.json",
            "ui_command_path": "state/endpoint_ui_command.json",
            "response_profile": "aggressive",
            "response_action_cooldown_seconds": 120,
            "response_allowlisted_process_names": ["TrustedUpdater.exe"],
            "response_allowlisted_process_paths": ["C:/Program Files/Trusted/updater.exe"]
        });

        AgentConfig::apply_json_overrides(&mut config, &payload);

        assert_eq!(config.response_profile, ResponseProfile::Aggressive);
        assert_eq!(config.ui_status_path, PathBuf::from("state/endpoint_ui_status.json"));
        assert_eq!(
            config.ui_command_path,
            PathBuf::from("state/endpoint_ui_command.json")
        );
        assert_eq!(config.response_action_cooldown_seconds, 120);
        assert!(config
            .response_allowlisted_process_names
            .contains("trustedupdater.exe"));
        assert!(config
            .response_allowlisted_process_paths
            .contains("c:/program files/trusted/updater.exe"));
    }

    #[test]
    fn parses_nested_response_overrides() {
        let mut config = AgentConfig::default();
        let payload = serde_json::json!({
            "response": {
                "profile": "contain",
                "cooldown_seconds": 45,
                "allowlisted_process_names": ["safeproc.exe"]
            }
        });

        AgentConfig::apply_json_overrides(&mut config, &payload);

        assert_eq!(config.response_profile, ResponseProfile::Contain);
        assert_eq!(config.response_action_cooldown_seconds, 45);
        assert!(config
            .response_allowlisted_process_names
            .contains("safeproc.exe"));
    }
}
