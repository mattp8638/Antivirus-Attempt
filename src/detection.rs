use std::collections::{HashMap, HashSet};

use crate::config::IocConfig;
use crate::models::{Alert, ConnectionInfo, Incident, ProcessInfo};



pub fn detect_suspicious_processes(processes: &[ProcessInfo], ioc: &IocConfig) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for process in processes {
        if ioc.blocked_process_names.contains(&process.name) {
            alerts.push(Alert::with_pid(
                "blocked_process_name",
                "high",
                format!(
                    "PID {} matched blocked process name {}",
                    process.pid, process.name
                ),
                process.pid,
            ));
        }
        for token in &ioc.blocked_command_substrings {
            if process.command.contains(token) {
                alerts.push(Alert::with_pid(
                    "blocked_command_substring",
                    "medium",
                    format!("PID {} command matched IOC token {}", process.pid, token),
                    process.pid,
                ));
            }
        }
    }
    alerts
}

pub fn detect_suspicious_connections(
    connections: &[ConnectionInfo],
    ioc: &IocConfig,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for conn in connections {
        if ioc.blocked_remote_ips.contains(&conn.remote_address) {
            let proc_name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let message = format!(
                "{} {}:{} -> {}:{} matched blocked remote IP (process={})",
                conn.protocol,
                conn.local_address,
                conn.local_port,
                conn.remote_address,
                conn.remote_port,
                proc_name
            );
            match conn.pid {
                Some(pid) => {
                    alerts.push(Alert::with_pid("blocked_remote_ip", "high", message, pid))
                }
                None => alerts.push(Alert::new("blocked_remote_ip", "high", message)),
            }
        }

        if ioc.blocked_remote_ports.contains(&conn.remote_port) {
            let proc_name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let message = format!(
                "{} {}:{} -> {}:{} matched blocked remote port (process={})",
                conn.protocol,
                conn.local_address,
                conn.local_port,
                conn.remote_address,
                conn.remote_port,
                proc_name
            );
            match conn.pid {
                Some(pid) => {
                    alerts.push(Alert::with_pid("blocked_remote_port", "high", message, pid))
                }
                None => alerts.push(Alert::new("blocked_remote_port", "high", message)),
            }
        }
    }

    alerts
}

pub fn correlate_incidents(alerts: &[Alert], risk_threshold: u32, ts_unix: u64) -> Vec<Incident> {
    let mut by_pid: HashMap<i32, Vec<&Alert>> = HashMap::new();
    for alert in alerts {
        if let Some(pid) = alert.pid {
            by_pid.entry(pid).or_default().push(alert);
        }
    }

    let mut incidents = Vec::new();
    for (pid, grouped) in by_pid {
        let risk_score: u32 = grouped.iter().map(|a| a.severity_weight()).sum();
        if risk_score < risk_threshold {
            continue;
        }
        let rules = grouped
            .iter()
            .map(|a| a.rule.as_str())
            .collect::<Vec<_>>()
            .join(",");
        incidents.push(Incident {
            incident_id: format!("inc-{}-{}", ts_unix, pid),
            primary_pid: pid,
            risk_score,
            alert_count: grouped.len(),
            summary: format!(
                "Correlated {} alerts for pid {} [{}]",
                grouped.len(),
                pid,
                rules
            ),
        });
    }

    incidents
}

pub fn detect_file_changes(
    previous: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> Vec<Alert> {
    let summary = summarize_file_changes(previous, current);
    let mut alerts = Vec::new();
    for (path, digest) in current {
        match previous.get(path) {
            None => alerts.push(Alert::new(
                "new_file_detected",
                "low",
                format!("New file observed: {path}"),
            )),
            Some(old) if old != digest => alerts.push(Alert::new(
                "file_modified",
                "medium",
                format!("File modified: {path}"),
            )),
            _ => {}
        }
    }
    for deleted in &summary.deleted_paths {
        alerts.push(Alert::new(
            "file_deleted",
            "medium",
            format!("File deleted: {deleted}"),
        ));
    }
    alerts
}

pub struct FileChangeSummary {
    pub created: usize,
    pub modified: usize,
    pub deleted: usize,
    pub deleted_paths: Vec<String>,
    pub changed_paths: Vec<String>,
}

pub fn summarize_file_changes(
    previous: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> FileChangeSummary {
    let mut created = 0;
    let mut modified = 0;
    let mut changed_paths = Vec::new();
    for (path, digest) in current {
        match previous.get(path) {
            None => {
                created += 1;
                changed_paths.push(path.clone());
            }
            Some(old) if old != digest => {
                modified += 1;
                changed_paths.push(path.clone());
            }
            _ => {}
        }
    }

    let mut deleted_paths = Vec::new();
    for deleted in previous.keys().filter(|k| !current.contains_key(*k)) {
        deleted_paths.push(deleted.clone());
    }
    deleted_paths.sort();
    changed_paths.sort();

    FileChangeSummary {
        created,
        modified,
        deleted: deleted_paths.len(),
        deleted_paths,
        changed_paths,
    }
}

pub fn detect_ransomware_activity(
    previous: &HashMap<String, String>,
    current: &HashMap<String, String>,
    change_threshold: usize,
    delete_threshold: usize,
    suspicious_extensions: &HashSet<String>,
    extension_threshold: usize,
    sample_limit: usize,
) -> Option<Alert> {
    let summary = summarize_file_changes(previous, current);
    let change_count = summary.created + summary.modified;
    let delete_count = summary.deleted;
    let mut extension_hits = 0;
    let mut extension_samples = Vec::new();
    for (path, digest) in current {
        let is_new_or_modified = match previous.get(path) {
            None => true,
            Some(old) => old != digest,
        };
        if !is_new_or_modified {
            continue;
        }
        let ext = std::path::Path::new(path)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
        if let Some(ext) = ext {
            if suspicious_extensions.contains(&ext) {
                extension_hits += 1;
                extension_samples.push(path.clone());
            }
        }
    }
    extension_samples.sort();
    if extension_samples.len() > sample_limit {
        extension_samples.truncate(sample_limit);
    }

    if change_count >= change_threshold
        || delete_count >= delete_threshold
        || extension_hits >= extension_threshold
    {
        let sample_suffix = if extension_samples.is_empty() {
            String::new()
        } else {
            format!(" sample_paths=[{}]", extension_samples.join(", "))
        };
        return Some(Alert::new(
            "ransomware_activity_suspected",
            "high",
            format!(
                "High volume file changes detected: created={} modified={} deleted={} suspicious_ext_hits={} thresholds=(change:{} delete:{} ext:{}){}",
                summary.created,
                summary.modified,
                summary.deleted,
                extension_hits,
                change_threshold,
                delete_threshold,
                extension_threshold,
                sample_suffix
            ),
        ));
    }
    None
}

pub fn detect_ransomware_note_files(
    previous: &HashMap<String, String>,
    current: &HashMap<String, String>,
    note_tokens: &HashSet<String>,
    note_threshold: usize,
    sample_limit: usize,
) -> Option<Alert> {
    if note_tokens.is_empty() {
        return None;
    }
    let mut hits = 0;
    let mut samples = Vec::new();
    for path in current.keys() {
        if previous.contains_key(path) {
            continue;
        }
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if note_tokens.iter().any(|t| name.contains(t)) {
            hits += 1;
            samples.push(path.clone());
        }
    }
    samples.sort();
    if samples.len() > sample_limit {
        samples.truncate(sample_limit);
    }
    if hits >= note_threshold {
        let sample_suffix = if samples.is_empty() {
            String::new()
        } else {
            format!(" sample_paths=[{}]", samples.join(", "))
        };
        return Some(Alert::new(
            "ransomware_note_suspected",
            "high",
            format!(
                "Ransom note files detected: hits={} threshold={}{}",
                hits, note_threshold, sample_suffix
            ),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IocConfig;
    use crate::models::ProcessInfo;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_ioc_detection() {
        let processes = vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                name: "ncat".into(),
                command: "ncat -lvp 4444".into(),
            },
            ProcessInfo {
                pid: 2,
                ppid: 0,
                name: "python".into(),
                command: "python --token a".into(),
            },
        ];
        let ioc = IocConfig {
            blocked_process_names: HashSet::from(["ncat".into()]),
            blocked_command_substrings: HashSet::from(["--token".into()]),
            blocked_remote_ips: HashSet::new(),
            blocked_remote_ports: HashSet::new(),
        };
        assert_eq!(detect_suspicious_processes(&processes, &ioc).len(), 2);
    }

    #[test]
    fn test_network_ioc_detection() {
        let conns = vec![ConnectionInfo {
            protocol: "tcp".into(),
            local_address: "127.0.0.1".into(),
            local_port: 1234,
            remote_address: "1.2.3.4".into(),
            remote_port: 443,
            pid: Some(99),
            process_name: Some("curl".into()),
        }];
        let ioc = IocConfig {
            blocked_process_names: HashSet::new(),
            blocked_command_substrings: HashSet::new(),
            blocked_remote_ips: HashSet::from(["1.2.3.4".into()]),
            blocked_remote_ports: HashSet::from([443]),
        };
        assert_eq!(detect_suspicious_connections(&conns, &ioc).len(), 2);
    }

    #[test]
    fn test_incident_correlation() {
        let alerts = vec![
            Alert::with_pid("a", "high", "m1".into(), 100),
            Alert::with_pid("b", "medium", "m2".into(), 100),
            Alert::with_pid("c", "high", "m3".into(), 200),
        ];
        let incidents = correlate_incidents(&alerts, 10, 123456);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].primary_pid, 100);
    }

    #[test]
    fn test_file_change_detection() {
        let prev = HashMap::from([
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
        let curr = HashMap::from([
            ("a".to_string(), "9".to_string()),
            ("c".to_string(), "3".to_string()),
        ]);
        assert_eq!(detect_file_changes(&prev, &curr).len(), 3);
    }

    #[test]
    fn test_ransomware_detection_thresholds() {
        let prev = HashMap::from([
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
        let curr = HashMap::from([
            ("a".to_string(), "9".to_string()),
            ("c".to_string(), "3".to_string()),
        ]);
        let alert = detect_ransomware_activity(&prev, &curr, 1, 10, &HashSet::new(), 5, 5);
        assert!(alert.is_some());
        let no_alert = detect_ransomware_activity(&prev, &curr, 5, 10, &HashSet::new(), 5, 5);
        assert!(no_alert.is_none());
    }

    #[test]
    fn test_ransomware_extension_threshold() {
        let prev = HashMap::new();
        let curr = HashMap::from([("report.locked".to_string(), "1".to_string())]);
        let extensions = HashSet::from([".locked".to_string()]);
        let alert = detect_ransomware_activity(&prev, &curr, 10, 10, &extensions, 1, 1);
        assert!(alert.is_some());
    }

    #[test]
    fn test_ransomware_sample_limit() {
        let prev = HashMap::new();
        let curr = HashMap::from([
            ("a.locked".to_string(), "1".to_string()),
            ("b.locked".to_string(), "2".to_string()),
        ]);
        let extensions = HashSet::from([".locked".to_string()]);
        let alert = detect_ransomware_activity(&prev, &curr, 10, 10, &extensions, 1, 1).unwrap();
        assert!(alert.message.contains("sample_paths=[a.locked]"));
        assert!(!alert.message.contains("b.locked"));
    }

    #[test]
    fn test_ransomware_note_detection() {
        let prev = HashMap::new();
        let curr = HashMap::from([
            ("notes/README_DECRYPT.txt".to_string(), "1".to_string()),
            ("notes/ignore.txt".to_string(), "2".to_string()),
        ]);
        let tokens = HashSet::from(["readme".to_string(), "decrypt".to_string()]);
        let alert = detect_ransomware_note_files(&prev, &curr, &tokens, 1, 2);
        assert!(alert.is_some());
    }

    #[test]
    fn test_summarize_file_changes_tracks_changed_paths() {
        let prev = HashMap::from([("a".to_string(), "1".to_string())]);
        let curr = HashMap::from([
            ("a".to_string(), "2".to_string()),
            ("b".to_string(), "1".to_string()),
        ]);
        let summary = summarize_file_changes(&prev, &curr);
        assert_eq!(summary.changed_paths.len(), 2);
        assert_eq!(
            summary.changed_paths,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn summarize_file_changes_sorts_deleted_paths() {
        let prev = HashMap::from([
            ("z".to_string(), "1".to_string()),
            ("a".to_string(), "1".to_string()),
        ]);
        let curr = HashMap::new();
        let summary = summarize_file_changes(&prev, &curr);
        assert_eq!(
            summary.deleted_paths,
            vec!["a".to_string(), "z".to_string()]
        );
    }
}
