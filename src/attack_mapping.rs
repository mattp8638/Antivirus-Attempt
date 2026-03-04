// ATT&CK Tactic and Technique Mapping Module
// Provides comprehensive mapping from detection rules to MITRE ATT&CK framework

use std::collections::HashMap;
use once_cell::sync::Lazy;

#[derive(Debug, Clone)]
pub struct AttackMapping {
    pub tactic: &'static str,
    pub technique: &'static str,
    pub tactic_id: &'static str,
    pub technique_id: &'static str,
    pub description: &'static str,
}

// Static mapping registry for all detection rules
static ATTACK_MAPPINGS: Lazy<HashMap<&'static str, AttackMapping>> = Lazy::new(|| {
    let mut map = HashMap::new();
    
    // Process-based detections
    map.insert("blocked_process_name", AttackMapping {
        tactic: "Execution",
        technique: "Command and Scripting Interpreter",
        tactic_id: "TA0002",
        technique_id: "T1059",
        description: "Suspicious process execution detected via process name blocking",
    });
    
    map.insert("blocked_command_substring", AttackMapping {
        tactic: "Execution",
        technique: "Command and Scripting Interpreter",
        tactic_id: "TA0002",
        technique_id: "T1059",
        description: "Malicious command pattern detected in process arguments",
    });
    
    // Network-based detections
    map.insert("blocked_remote_ip", AttackMapping {
        tactic: "Command and Control",
        technique: "Application Layer Protocol",
        tactic_id: "TA0011",
        technique_id: "T1071",
        description: "Connection to known malicious IP address",
    });
    
    map.insert("blocked_remote_port", AttackMapping {
        tactic: "Command and Control",
        technique: "Non-Standard Port",
        tactic_id: "TA0011",
        technique_id: "T1571",
        description: "Connection to suspicious or blocked port",
    });
    
    // File Integrity Monitoring detections
    map.insert("new_file_detected", AttackMapping {
        tactic: "Defense Evasion",
        technique: "Masquerading",
        tactic_id: "TA0005",
        technique_id: "T1036",
        description: "New file created in monitored directory",
    });
    
    map.insert("file_modified", AttackMapping {
        tactic: "Defense Evasion",
        technique: "Indicator Removal",
        tactic_id: "TA0005",
        technique_id: "T1070",
        description: "File modification in monitored directory",
    });
    
    map.insert("file_deleted", AttackMapping {
        tactic: "Impact",
        technique: "Data Destruction",
        tactic_id: "TA0040",
        technique_id: "T1485",
        description: "File deletion in monitored directory",
    });
    
    // Ransomware detections
    map.insert("ransomware_activity_suspected", AttackMapping {
        tactic: "Impact",
        technique: "Data Encrypted for Impact",
        tactic_id: "TA0040",
        technique_id: "T1486",
        description: "High-volume file modifications consistent with ransomware encryption",
    });
    
    map.insert("ransomware_note_suspected", AttackMapping {
        tactic: "Impact",
        technique: "Data Encrypted for Impact",
        tactic_id: "TA0040",
        technique_id: "T1486",
        description: "Ransomware note file detected",
    });
    
    map.insert("yara_match", AttackMapping {
        tactic: "Execution",
        technique: "Malicious File",
        tactic_id: "TA0002",
        technique_id: "T1204.002",
        description: "YARA signature match on file",
    });
    
    // Memory-based detections
    map.insert("process_injection_suspected", AttackMapping {
        tactic: "Defense Evasion",
        technique: "Process Injection",
        tactic_id: "TA0005",
        technique_id: "T1055",
        description: "Suspicious memory allocation pattern detected",
    });
    
    map.insert("privilege_escalation_attempt", AttackMapping {
        tactic: "Privilege Escalation",
        technique: "Abuse Elevation Control Mechanism",
        tactic_id: "TA0004",
        technique_id: "T1548",
        description: "Privilege escalation behavior detected",
    });
    
    // Windows-specific detections
    map.insert("shadow_copy_deletion", AttackMapping {
        tactic: "Impact",
        technique: "Inhibit System Recovery",
        tactic_id: "TA0040",
        technique_id: "T1490",
        description: "Shadow copy deletion detected - common ransomware precursor",
    });
    
    map.insert("credential_access_attempt", AttackMapping {
        tactic: "Credential Access",
        technique: "OS Credential Dumping",
        tactic_id: "TA0006",
        technique_id: "T1003",
        description: "Credential dumping or access attempt detected",
    });
    
    map.insert("lateral_movement_detected", AttackMapping {
        tactic: "Lateral Movement",
        technique: "Remote Services",
        tactic_id: "TA0008",
        technique_id: "T1021",
        description: "Lateral movement via remote service detected",
    });
    
    map.insert("persistence_mechanism", AttackMapping {
        tactic: "Persistence",
        technique: "Boot or Logon Autostart Execution",
        tactic_id: "TA0003",
        technique_id: "T1547",
        description: "Persistence mechanism installation detected",
    });
    
    map.insert("suspicious_powershell", AttackMapping {
        tactic: "Execution",
        technique: "PowerShell",
        tactic_id: "TA0002",
        technique_id: "T1059.001",
        description: "Suspicious PowerShell execution detected",
    });
    
    map.insert("suspicious_wmi", AttackMapping {
        tactic: "Execution",
        technique: "Windows Management Instrumentation",
        tactic_id: "TA0002",
        technique_id: "T1047",
        description: "Suspicious WMI activity detected",
    });
    
    map.insert("scheduled_task_creation", AttackMapping {
        tactic: "Persistence",
        technique: "Scheduled Task/Job",
        tactic_id: "TA0003",
        technique_id: "T1053",
        description: "Suspicious scheduled task creation",
    });
    
    map.insert("service_creation", AttackMapping {
        tactic: "Persistence",
        technique: "Create or Modify System Process",
        tactic_id: "TA0003",
        technique_id: "T1543",
        description: "Suspicious service creation or modification",
    });
    
    map.insert("registry_modification", AttackMapping {
        tactic: "Defense Evasion",
        technique: "Modify Registry",
        tactic_id: "TA0005",
        technique_id: "T1112",
        description: "Suspicious registry modification detected",
    });
    
    map.insert("dll_hijacking", AttackMapping {
        tactic: "Defense Evasion",
        technique: "Hijack Execution Flow",
        tactic_id: "TA0005",
        technique_id: "T1574",
        description: "DLL hijacking or sideloading detected",
    });
    
    map
});

/// Get ATT&CK mapping for a given rule
pub fn get_mapping(rule: &str) -> Option<&'static AttackMapping> {
    ATTACK_MAPPINGS.get(rule)
}

/// Get all available mappings (for documentation/export)
pub fn list_all_mappings() -> Vec<(&'static str, &'static AttackMapping)> {
    ATTACK_MAPPINGS.iter().map(|(k, v)| (*k, v)).collect()
}

/// Get unique tactics from all mappings
pub fn get_all_tactics() -> Vec<&'static str> {
    let mut tactics: Vec<_> = ATTACK_MAPPINGS
        .values()
        .map(|m| m.tactic)
        .collect();
    tactics.sort_unstable();
    tactics.dedup();
    tactics
}

/// Get unique techniques from all mappings
pub fn get_all_techniques() -> Vec<&'static str> {
    let mut techniques: Vec<_> = ATTACK_MAPPINGS
        .values()
        .map(|m| m.technique)
        .collect();
    techniques.sort_unstable();
    techniques.dedup();
    techniques
}

/// Get all rules that map to a specific tactic
pub fn get_rules_by_tactic(tactic_id: &str) -> Vec<&'static str> {
    ATTACK_MAPPINGS
        .iter()
        .filter(|(_, m)| m.tactic_id == tactic_id)
        .map(|(rule, _)| *rule)
        .collect()
}

/// Get all rules that map to a specific technique
pub fn get_rules_by_technique(technique_id: &str) -> Vec<&'static str> {
    ATTACK_MAPPINGS
        .iter()
        .filter(|(_, m)| m.technique_id == technique_id)
        .map(|(rule, _)| *rule)
        .collect()
}

/// Generate ATT&CK Navigator layer JSON (for visualization)
pub fn export_navigator_layer() -> serde_json::Value {
    use serde_json::json;
    
    let techniques: Vec<_> = ATTACK_MAPPINGS
        .values()
        .map(|m| {
            json!({
                "techniqueID": m.technique_id,
                "tactic": m.tactic.to_lowercase().replace(' ', "-"),
                "enabled": true,
                "score": ATTACK_MAPPINGS
                    .values()
                    .filter(|other| other.technique_id == m.technique_id)
                    .count()
            })
        })
        .collect();
    
    json!({
        "name": "TamsilCMS Sentinel EDR Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "ATT&CK technique coverage for TamsilCMS Sentinel EDR",
        "techniques": techniques
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_exists() {
        let mapping = get_mapping("blocked_process_name");
        assert!(mapping.is_some());
        assert_eq!(mapping.unwrap().tactic, "Execution");
    }

    #[test]
    fn test_all_tactics() {
        let tactics = get_all_tactics();
        assert!(!tactics.is_empty());
        assert!(tactics.contains(&"Execution"));
        assert!(tactics.contains(&"Command and Control"));
    }

    #[test]
    fn test_rules_by_tactic() {
        let rules = get_rules_by_tactic("TA0002");
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_rules_by_technique() {
        let rules = get_rules_by_technique("T1486");
        assert!(rules.contains(&"ransomware_activity_suspected"));
        assert!(rules.contains(&"ransomware_note_suspected"));
    }

    #[test]
    fn test_navigator_export() {
        let layer = export_navigator_layer();
        assert!(layer["techniques"].is_array());
        assert!(!layer["techniques"].as_array().unwrap().is_empty());
    }
}
