use crate::models::Alert;

pub fn normalize_alerts(alerts: &mut [Alert]) {
    for alert in alerts {
        apply_attack_mapping(alert);
        apply_intel_tags(alert);
    }
}

fn apply_attack_mapping(alert: &mut Alert) {
    match alert.rule.as_str() {
        "ransomware_activity_suspected" | "ransomware_note_suspected" => {
            alert.set_attack("Impact", "T1486 Data Encrypted for Impact");
        }
        "blocked_process_name" | "blocked_command_substring" => {
            alert.set_attack("Execution", "T1059 Command and Scripting Interpreter");
        }
        "blocked_remote_ip" | "blocked_remote_port" => {
            alert.set_attack("Command and Control", "T1071 Application Layer Protocol");
        }
        "memory_injection_detected" | "memory_protection_change" => {
            alert.set_attack("Defense Evasion", "T1055 Process Injection");
        }
        "memory_triggered_threat_detected" | "memory_triggered_scan_failed" => {
            alert.set_attack("Defense Evasion", "T1055 Process Injection");
        }
        "memory_on_demand_threat_detected" | "ui_memory_scan_failed" => {
            alert.set_attack("Defense Evasion", "T1055 Process Injection");
        }
        "response_process_terminated"
        | "response_process_termination_failed"
        | "response_file_quarantined"
        | "response_file_quarantine_failed"
        | "response_file_path_unresolved"
        | "response_skipped_profile_detect_only"
        | "response_skipped_allowlist"
        | "response_skipped_cooldown" => {
            alert.set_attack("Impact", "T1489 Service Stop");
        }
        "lsass_access_detected" => {
            alert.set_attack(
                "Credential Access",
                "T1003.001 OS Credential Dumping: LSASS Memory",
            );
        }
        "behavioral_office_script" => {
            alert.set_attack("Execution", "T1059.001 PowerShell");
        }
        "behavioral_services_unusual" => {
            alert.set_attack("Persistence", "T1543.003 Windows Service");
        }
        "behavioral_powershell_encoded" | "behavioral_command_obfuscation" => {
            alert.set_attack("Defense Evasion", "T1027 Obfuscated Files or Information");
        }
        "behavioral_download_cradle" => {
            alert.set_attack("Command and Control", "T1105 Ingress Tool Transfer");
        }
        "behavioral_lolbin_abuse" => {
            alert.set_attack("Defense Evasion", "T1218 Signed Binary Proxy Execution");
        }
        "behavioral_process_tree_risk" => {
            alert.set_attack("Execution", "T1059 Command and Scripting Interpreter");
        }
        "behavioral_process_lineage_depth" => {
            alert.set_attack("Discovery", "T1082 System Information Discovery");
        }
        "behavioral_memory_scan_trigger" => {
            alert.set_attack("Defense Evasion", "T1055 Process Injection");
        }
        "ui_command_received"
        | "ui_quick_scan_completed"
        | "ui_full_scan_completed"
        | "ui_memory_scan_completed"
        | "ui_command_read_failed" => {
            alert.set_attack("Execution", "T1059 Command and Scripting Interpreter");
        }
        "fim_violation" => {
            alert.set_attack("Defense Evasion", "T1070 Indicator Removal");
        }
        _ => {}
    }
}

fn apply_intel_tags(alert: &mut Alert) {
    match alert.rule.as_str() {
        "blocked_process_name" => alert.add_tag("ioc:process"),
        "blocked_command_substring" => alert.add_tag("ioc:command"),
        "blocked_remote_ip" => alert.add_tag("ioc:ip"),
        "blocked_remote_port" => alert.add_tag("ioc:port"),
        "ransomware_activity_suspected" | "ransomware_note_suspected" => {
            alert.add_tag("ransomware");
        }
        "yara_match_detected" => alert.add_tag("yara"),
        "memory_injection_detected"
        | "memory_protection_change"
        | "memory_triggered_threat_detected"
        | "memory_triggered_scan_failed"
        | "memory_on_demand_threat_detected"
        | "ui_memory_scan_failed" => {
            alert.add_tag("memory");
        }
        "response_process_terminated"
        | "response_process_termination_failed"
        | "response_file_quarantined"
        | "response_file_quarantine_failed"
        | "response_file_path_unresolved"
        | "response_skipped_profile_detect_only"
        | "response_skipped_allowlist"
        | "response_skipped_cooldown" => {
            alert.add_tag("response");
        }
        "lsass_access_detected" => {
            alert.add_tag("credential_access");
        }
        "behavioral_office_script"
        | "behavioral_services_unusual"
        | "behavioral_powershell_encoded"
        | "behavioral_command_obfuscation"
        | "behavioral_download_cradle"
        | "behavioral_lolbin_abuse"
        | "behavioral_process_tree_risk"
        | "behavioral_process_lineage_depth"
        | "behavioral_memory_scan_trigger" => {
            alert.add_tag("behavioral");
        }
        "fim_violation" => {
            alert.add_tag("fim");
        }
        "ui_command_received"
        | "ui_quick_scan_completed"
        | "ui_full_scan_completed"
        | "ui_memory_scan_completed"
        | "ui_command_read_failed" => {
            alert.add_tag("ui");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ransomware_alerts_to_attack() {
        let mut alerts = vec![Alert::new(
            "ransomware_activity_suspected",
            "high",
            "hit".into(),
        )];
        normalize_alerts(&mut alerts);
        let alert = &alerts[0];
        assert_eq!(alert.attack_tactic.as_deref(), Some("Impact"));
        assert!(alert
            .attack_technique
            .as_deref()
            .unwrap_or_default()
            .contains("T1486"));
        assert!(alert.intel_tags.iter().any(|t| t == "ransomware"));
    }

    #[test]
    fn tags_ioc_blocked_ip() {
        let mut alerts = vec![Alert::new("blocked_remote_ip", "high", "hit".into())];
        normalize_alerts(&mut alerts);
        let alert = &alerts[0];
        assert_eq!(alert.attack_tactic.as_deref(), Some("Command and Control"));
        assert!(alert.intel_tags.iter().any(|t| t == "ioc:ip"));
    }
}
