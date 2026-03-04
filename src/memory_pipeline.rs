use std::time::{SystemTime, UNIX_EPOCH};

use crate::memory_analyzer::{MemoryAlert, MemoryAlertSeverity, MemoryAnalyzer};
use crate::memory_events::{InjectionEvent, LsassAccessEvent, MemProtEvent};
use crate::models::Alert;
use serde_json::json;

pub struct MemoryPipeline {
    analyzer: MemoryAnalyzer,
}

impl MemoryPipeline {
    pub fn new() -> Self {
        Self {
            analyzer: MemoryAnalyzer::new(),
        }
    }

    pub fn handle_injection_event(&self, ev: InjectionEvent) -> (Alert, MemoryAlert) {
        let alert: MemoryAlert = self.analyzer.analyze_injection(&ev);
        let out = Self::alert_from_injection("memory_injection_detected", &ev, alert.clone());
        (out, alert)
    }

    pub fn handle_memprot_event(&self, ev: MemProtEvent) -> Option<(Alert, MemoryAlert)> {
        let alert = self.analyzer.analyze_mem_prot(&ev)?;
        let out = Self::alert_from_memprot("memory_protection_change", &ev, alert.clone());
        Some((out, alert))
    }

    pub fn handle_lsass_access_event(&self, ev: LsassAccessEvent) -> Option<(Alert, MemoryAlert)> {
        let alert = self.analyzer.analyze_lsass_access(&ev)?;
        let out = Self::alert_from_lsass("lsass_access_detected", &ev, alert.clone());
        Some((out, alert))
    }

    fn alert_from_memory(rule: &str, alert: MemoryAlert) -> Alert {
        let severity = match alert.severity {
            MemoryAlertSeverity::Low => "low",
            MemoryAlertSeverity::Medium => "medium",
            MemoryAlertSeverity::High => "high",
            MemoryAlertSeverity::Critical => "critical",
        };
        let mut out = Alert::new(rule, severity, alert.description);
        out.pid = Some(alert.source_pid as i32);
        out
    }

    fn alert_from_injection(rule: &str, ev: &InjectionEvent, alert: MemoryAlert) -> Alert {
        let mitre = alert.mitre_techniques.clone();
        let mut out = Self::alert_from_memory(rule, alert);
        out.set_details(json!({
            "source_pid": ev.source_pid,
            "source_image": ev.source_image.clone(),
            "target_pid": ev.target_pid,
            "target_image": ev.target_image.clone(),
            "technique_hint": format!("{:?}", ev.technique_hint),
            "timestamp_unix": system_time_to_unix(ev.timestamp),
            "mitre_techniques": mitre,
        }));
        out
    }

    fn alert_from_memprot(rule: &str, ev: &MemProtEvent, alert: MemoryAlert) -> Alert {
        let mitre = alert.mitre_techniques.clone();
        let mut out = Self::alert_from_memory(rule, alert);
        out.set_details(json!({
            "pid": ev.pid,
            "process_image": ev.process_image.clone(),
            "address": ev.address,
            "size": ev.size,
            "old_protection": ev.old_protection,
            "new_protection": ev.new_protection,
            "timestamp_unix": system_time_to_unix(ev.timestamp),
            "mitre_techniques": mitre,
        }));
        out
    }

    fn alert_from_lsass(rule: &str, ev: &LsassAccessEvent, alert: MemoryAlert) -> Alert {
        let mitre = alert.mitre_techniques.clone();
        let mut out = Self::alert_from_memory(rule, alert);
        out.set_details(json!({
            "source_pid": ev.source_pid,
            "source_image": ev.source_image.clone(),
            "access_mask": ev.access_mask,
            "timestamp_unix": system_time_to_unix(ev.timestamp),
            "mitre_techniques": mitre,
        }));
        out
    }
}

fn system_time_to_unix(ts: SystemTime) -> Option<u64> {
    ts.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}
