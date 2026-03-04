use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::config::ResponseProfile;

#[derive(Debug, Clone, Default)]
pub struct PolicyOverrides {
    pub blocked_process_names: HashSet<String>,
    pub blocked_command_substrings: HashSet<String>,
    pub blocked_remote_ips: HashSet<String>,
    pub blocked_remote_ports: HashSet<u16>,
    pub suspicious_file_extensions: HashSet<String>,
    pub response_allowlisted_process_names: HashSet<String>,
    pub response_allowlisted_process_paths: HashSet<String>,
    pub response_profile: Option<ResponseProfile>,
    pub response_action_cooldown_seconds: Option<u64>,
}

pub fn load_policy(path: &Path) -> Result<PolicyOverrides, String> {
    if !path.exists() {
        return Ok(PolicyOverrides::default());
    }

    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut out = PolicyOverrides::default();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some(v) => v,
            None => continue,
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match key {
            "block_name" => {
                out.blocked_process_names.insert(value.to_lowercase());
            }
            "block_cmd" => {
                out.blocked_command_substrings.insert(value.to_lowercase());
            }
            "block_ip" => {
                out.blocked_remote_ips.insert(value.to_lowercase());
            }
            "block_port" => {
                if let Ok(p) = value.parse::<u16>() {
                    out.blocked_remote_ports.insert(p);
                }
            }
            "suspicious_ext" => {
                let normalized = if value.starts_with('.') {
                    value.to_lowercase()
                } else {
                    format!(".{}", value.to_lowercase())
                };
                out.suspicious_file_extensions.insert(normalized);
            }
            "response_allow_name" => {
                out.response_allowlisted_process_names
                    .insert(value.to_lowercase());
            }
            "response_allow_path" => {
                out.response_allowlisted_process_paths
                    .insert(value.to_lowercase());
            }
            "response_profile" => {
                out.response_profile = match value.to_ascii_lowercase().as_str() {
                    "detect_only" => Some(ResponseProfile::DetectOnly),
                    "contain" => Some(ResponseProfile::Contain),
                    "aggressive" => Some(ResponseProfile::Aggressive),
                    _ => None,
                }
            }
            "response_cooldown_seconds" => {
                if let Ok(cooldown) = value.parse::<u64>() {
                    if cooldown > 0 {
                        out.response_action_cooldown_seconds = Some(cooldown);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_file() {
        let path = std::env::temp_dir().join(format!("policy_test_{}.conf", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "block_name=ncat\nblock_cmd=--token\nblock_ip=1.2.3.4\nblock_port=443\nsuspicious_ext=sh\nresponse_allow_name=trustedupdater.exe\nresponse_allow_path=C:\\Program Files\\Trusted\\updater.exe\nresponse_profile=contain\nresponse_cooldown_seconds=120\n",
        )
        .unwrap();

        let pol = load_policy(&path).unwrap();
        assert!(pol.blocked_process_names.contains("ncat"));
        assert!(pol.blocked_command_substrings.contains("--token"));
        assert!(pol.blocked_remote_ips.contains("1.2.3.4"));
        assert!(pol.blocked_remote_ports.contains(&443));
        assert!(pol.suspicious_file_extensions.contains(".sh"));
        assert!(pol
            .response_allowlisted_process_names
            .contains("trustedupdater.exe"));
        assert!(pol
            .response_allowlisted_process_paths
            .contains("c:\\program files\\trusted\\updater.exe"));
        assert_eq!(pol.response_profile, Some(ResponseProfile::Contain));
        assert_eq!(pol.response_action_cooldown_seconds, Some(120));
        let _ = std::fs::remove_file(&path);
    }
}
