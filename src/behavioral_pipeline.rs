use crate::behavioral_analyzer::{AlertSeverity, BehavioralAlert, BehavioralAnalyzer};
use crate::behavioral_events::ProcessEvent;
use crate::models::Alert;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub struct BehavioralPipeline {
    analyzer: BehavioralAnalyzer,
    tracker: Arc<Mutex<ProcessTreeTracker>>,
}

impl BehavioralPipeline {
    pub fn new() -> Self {
        Self {
            analyzer: BehavioralAnalyzer::new(),
            tracker: Arc::new(Mutex::new(ProcessTreeTracker::new())),
        }
    }

    pub fn handle_process_event(&self, ev: ProcessEvent) -> Vec<Alert> {
        let alerts = self.analyzer.analyze_process_start(&ev);
        let mut mapped_alerts: Vec<Alert> = alerts
            .into_iter()
            .map(Self::alert_from_behavioral)
            .collect();

        if let Ok(mut tracker) = self.tracker.lock() {
            let mut tree_alerts = tracker.ingest_event(&ev, &mapped_alerts);
            mapped_alerts.append(&mut tree_alerts);
        }

        mapped_alerts
    }

    pub fn drain_memory_scan_triggers(&self) -> Vec<u32> {
        if let Ok(mut tracker) = self.tracker.lock() {
            return tracker.drain_memory_scan_triggers();
        }
        Vec::new()
    }

    fn alert_from_behavioral(alert: BehavioralAlert) -> Alert {
        let severity = match alert.severity {
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        };
        let rule = match alert.title.as_str() {
            "Office Application Spawned Script Interpreter" => "behavioral_office_script",
            "Services.exe Spawned Unusual Child Process" => "behavioral_services_unusual",
            "PowerShell Encoded Command" => "behavioral_powershell_encoded",
            "Command-Line Obfuscation Detected" => "behavioral_command_obfuscation",
            "Potential Download Cradle Detected" => "behavioral_download_cradle",
            "LOLBin Abuse Detected" => "behavioral_lolbin_abuse",
            _ => "behavioral_alert",
        };
        let mut out = Alert::new(rule, severity, alert.description);
        out.pid = Some(alert.pid as i32);
        out
    }
}

#[derive(Debug, Clone)]
struct ProcessTreeNode {
    pid: u32,
    ppid: u32,
    image: String,
    command_line: String,
    first_seen: SystemTime,
    cumulative_risk: u32,
}

struct ProcessTreeTracker {
    nodes: HashMap<u32, ProcessTreeNode>,
    memory_scan_triggers: Vec<u32>,
}

impl ProcessTreeTracker {
    const TREE_RISK_THRESHOLD: u32 = 14;
    const MAX_PROPAGATION_DEPTH: usize = 8;

    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            memory_scan_triggers: Vec::new(),
        }
    }

    fn ingest_event(&mut self, ev: &ProcessEvent, behavioral_alerts: &[Alert]) -> Vec<Alert> {
        let node = self.nodes.entry(ev.pid).or_insert_with(|| ProcessTreeNode {
            pid: ev.pid,
            ppid: ev.ppid,
            image: ev.image_path.clone(),
            command_line: ev.command_line.clone(),
            first_seen: ev.timestamp,
            cumulative_risk: 0,
        });

        node.ppid = ev.ppid;
        node.image = ev.image_path.clone();
        node.command_line = ev.command_line.clone();

        let direct_risk: u32 = behavioral_alerts.iter().map(|a| a.severity_weight()).sum();
        if direct_risk == 0 {
            return self.depth_alerts(ev);
        }

        let mut alerts = self.depth_alerts(ev);
        self.propagate_risk(ev.pid, direct_risk);

        if let Some(updated) = self.nodes.get(&ev.pid) {
            if updated.cumulative_risk >= Self::TREE_RISK_THRESHOLD {
                let mut alert = Alert::with_pid(
                    "behavioral_process_tree_risk",
                    "high",
                    format!(
                        "Process tree risk threshold exceeded for PID {} (score={})",
                        updated.pid, updated.cumulative_risk
                    ),
                    updated.pid as i32,
                );
                alert.set_details(json!({
                    "pid": updated.pid,
                    "ppid": updated.ppid,
                    "image": updated.image,
                    "command_line": updated.command_line,
                    "cumulative_risk": updated.cumulative_risk,
                }));
                alerts.push(alert);
                self.queue_memory_scan(updated.pid);
            }
        }

        alerts
    }

    fn depth_alerts(&self, ev: &ProcessEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let (depth, from_shell) = self.lineage_depth(ev.pid);
        if from_shell && depth > 5 {
            let mut alert = Alert::with_pid(
                "behavioral_process_lineage_depth",
                "medium",
                format!(
                    "Deep process lineage from interactive shell detected (depth={}, pid={})",
                    depth, ev.pid
                ),
                ev.pid as i32,
            );
            alert.set_details(json!({
                "pid": ev.pid,
                "lineage_depth": depth,
                "interactive_shell_ancestor": true,
            }));
            alerts.push(alert);
        }
        alerts
    }

    fn propagate_risk(&mut self, start_pid: u32, direct_risk: u32) {
        let mut risk = direct_risk;
        let mut current = Some(start_pid);

        for _ in 0..Self::MAX_PROPAGATION_DEPTH {
            let pid = match current {
                Some(value) => value,
                None => break,
            };

            let node = match self.nodes.get_mut(&pid) {
                Some(value) => value,
                None => break,
            };

            node.cumulative_risk = node.cumulative_risk.saturating_add(risk);
            current = if node.ppid == 0 || node.ppid == node.pid {
                None
            } else {
                Some(node.ppid)
            };

            if risk <= 1 {
                break;
            }
            risk = (risk / 2).max(1);
        }
    }

    fn lineage_depth(&self, pid: u32) -> (usize, bool) {
        let mut depth = 0usize;
        let mut current = Some(pid);
        let mut seen_shell = false;

        for _ in 0..Self::MAX_PROPAGATION_DEPTH {
            let value = match current {
                Some(v) => v,
                None => break,
            };

            let node = match self.nodes.get(&value) {
                Some(v) => v,
                None => break,
            };

            depth += 1;
            if is_interactive_shell(&node.image) {
                seen_shell = true;
            }

            current = if node.ppid == 0 || node.ppid == node.pid {
                None
            } else {
                Some(node.ppid)
            };
        }

        (depth, seen_shell)
    }

    fn queue_memory_scan(&mut self, pid: u32) {
        if !self.memory_scan_triggers.contains(&pid) {
            self.memory_scan_triggers.push(pid);
        }
    }

    fn drain_memory_scan_triggers(&mut self) -> Vec<u32> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.memory_scan_triggers);
        out
    }
}

fn is_interactive_shell(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"]
        .iter()
        .any(|name| lower.ends_with(name))
}
