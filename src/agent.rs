use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::behavioral_events::ProcessEvent;
use crate::behavioral_pipeline::BehavioralPipeline;
use crate::backend_client::BackendClient;
use crate::collectors::{build_file_snapshot, collect_network_connections, collect_processes};
use crate::config::{AgentConfig, ResponseProfile};
use crate::detection::{
    correlate_incidents, detect_file_changes, detect_ransomware_activity,
    detect_ransomware_note_files, detect_suspicious_connections, detect_suspicious_processes,
    summarize_file_changes,
};
use crate::fim_engine::{FIMConfig, FIMEngine, FIMReporter, FIMViolation, FIMViolationType};
use crate::ingestion::{
    ingest_kernel_events_since, ingest_memory_events_since, ingest_windows_events_since,
    MemoryEventRecord,
};
use crate::intel::normalize_alerts;
use crate::memory_events::{InjectionEvent, LsassAccessEvent, MemProtEvent};
use crate::memory_pipeline::MemoryPipeline;
use crate::memory_scanner_edr::{MemoryScanner, ThreatSeverity as MemoryThreatSeverity};
use crate::models::{escape_json, Alert};
use crate::policy::load_policy;
use crate::state::AgentState;
use crate::telemetry::{publish_or_spool, write_heartbeat};
use anyhow::Result;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
enum UiCommandAction {
    QuickScan,
    FullScan,
    MemoryScan,
    RestoreQuarantine {
        target_path: String,
        restore_to_original: bool,
    },
    DeleteQuarantine { target_path: String },
    Unknown(String),
}

pub struct EdrAgent {
    pub config: AgentConfig,
    state: AgentState,
    kernel_event_recent: HashMap<String, u64>,
    windows_event_recent: HashMap<String, u64>,
    yara_recent_matches: HashMap<String, u64>,
    memory_event_recent: HashMap<String, u64>,
    response_action_recent: HashMap<String, u64>,
    memory_pipeline: MemoryPipeline,
    memory_scanner: MemoryScanner,
    behavioral_pipeline: BehavioralPipeline,
    fim_handle: Option<thread::JoinHandle<()>>,
    backend_client: Option<Arc<BackendClient>>,
}

impl Drop for EdrAgent {
    fn drop(&mut self) {
        if let Some(handle) = self.fim_handle.take() {
            let _ = handle.join();
        }
    }
}

impl EdrAgent {
    pub fn new(config: AgentConfig) -> Result<Self, String> {
        config.validate()?;
        let state = AgentState::load(&config.state_path)?;
        let backend_client = if config.backend_enabled {
            match BackendClient::new(config.backend_url.clone(), config.backend_endpoint_id) {
                Ok(client) => Some(Arc::new(client)),
                Err(e) => return Err(format!("backend client init failed: {e}")),
            }
        } else {
            None
        };
        let fim_handle = start_fim_worker(&config, backend_client.clone())?;
        Ok(Self {
            config,
            state,
            kernel_event_recent: HashMap::new(),
            windows_event_recent: HashMap::new(),
            yara_recent_matches: HashMap::new(),
            memory_event_recent: HashMap::new(),
            response_action_recent: HashMap::new(),
            memory_pipeline: MemoryPipeline::new(),
            memory_scanner: MemoryScanner::new(),
            behavioral_pipeline: BehavioralPipeline::new(),
            fim_handle,
            backend_client,
        })
    }

    pub fn scan_once(&mut self) -> Result<Vec<Alert>, String> {
        let scan_start_instant = Instant::now();
        let scan_ts = now_unix()?;
        let mut alerts = Vec::new();
        let mut ui_command = match self.consume_ui_command() {
            Ok(value) => value,
            Err(err) => {
                alerts.push(Alert::new(
                    "ui_command_read_failed",
                    "low",
                    format!("UI command read failed: {err}"),
                ));
                None
            }
        };

        if let Some(command) = &ui_command {
            alerts.push(Alert::new(
                "ui_command_received",
                "low",
                format!("Received UI command: {}", ui_command_name(command)),
            ));

            match command {
                UiCommandAction::RestoreQuarantine {
                    target_path,
                    restore_to_original,
                } => {
                    match restore_quarantined_file(
                        target_path,
                        &self.config.quarantine_dir,
                        *restore_to_original,
                    ) {
                        Ok(restored_path) => alerts.push(Alert::new(
                            "ui_quarantine_restore_completed",
                            "low",
                            format!(
                                "Restored quarantined file {} to {}",
                                target_path,
                                restored_path.display()
                            ),
                        )),
                        Err(err) => alerts.push(Alert::new(
                            "ui_quarantine_restore_failed",
                            "medium",
                            format!("Restore failed for {}: {}", target_path, err),
                        )),
                    }
                    ui_command = None;
                }
                UiCommandAction::DeleteQuarantine { target_path } => {
                    match delete_quarantined_file(target_path, &self.config.quarantine_dir) {
                        Ok(()) => alerts.push(Alert::new(
                            "ui_quarantine_delete_completed",
                            "low",
                            format!("Deleted quarantined file {}", target_path),
                        )),
                        Err(err) => alerts.push(Alert::new(
                            "ui_quarantine_delete_failed",
                            "medium",
                            format!("Delete failed for {}: {}", target_path, err),
                        )),
                    }
                    ui_command = None;
                }
                _ => {}
            }
        }

        let scan_mode = scan_mode_from_command(ui_command.as_ref());
        let _ = self.write_scan_status(
            scan_ts,
            &[],
            &[],
            "running",
            scan_mode,
            scan_ts,
            None,
            0,
            "Scan started",
        );

        if let Err(e) = self.refresh_yara_rules(scan_ts) {
            alerts.push(Alert::new(
                "yara_rules_fetch_failed",
                "medium",
                format!("Yara rules fetch failed: {e}"),
            ));
        }

        if self.config.kernel_ingestion_enabled {
            match ingest_kernel_events_since(
                self.state.kernel_cursor_unix,
                &self.config.kernel_ingestion_keywords,
                self.config.kernel_event_limit,
                self.config.kernel_use_audit_search,
            ) {
                Ok(events) => {
                    let processed_events = build_processed_kernel_events(
                        events,
                        scan_ts,
                        self.state.kernel_cursor_unix,
                    );
                    if let Err(e) = self.write_kernel_events(&processed_events) {
                        alerts.push(Alert::new(
                            "kernel_event_log_failed",
                            "medium",
                            format!("kernel event log failed: {e}"),
                        ));
                    }

                    for (ev, event_ts) in processed_events {
                        if !self.should_emit_kernel_event(&ev, event_ts) {
                            if event_ts > self.state.kernel_cursor_unix {
                                self.state.kernel_cursor_unix = event_ts;
                            }
                            continue;
                        }

                        alerts.push(Alert::new(
                            "kernel_event_signal",
                            &ev.severity,
                            format!("[{}:{}] {}", ev.source, ev.kind, ev.message),
                        ));
                        if event_ts > self.state.kernel_cursor_unix {
                            self.state.kernel_cursor_unix = event_ts;
                        }
                    }
                }
                Err(e) => alerts.push(Alert::new(
                    "kernel_ingestion_failed",
                    "medium",
                    format!("Kernel ingestion failed: {e}"),
                )),
            }
        }

        if self.config.windows_ingestion_enabled {
            match ingest_windows_events_since(
                self.state.windows_cursor_unix,
                &self.config.windows_event_channels,
                &self.config.windows_event_ids,
                self.config.windows_event_limit,
            ) {
                Ok(events) => {
                    let processed_events = build_processed_kernel_events(
                        events,
                        scan_ts,
                        self.state.windows_cursor_unix,
                    );
                    if let Err(e) = self.write_windows_events(&processed_events) {
                        alerts.push(Alert::new(
                            "windows_event_log_failed",
                            "medium",
                            format!("windows event log failed: {e}"),
                        ));
                    }

                    for (ev, event_ts) in processed_events {
                        if !self.should_emit_windows_event(&ev, event_ts) {
                            if event_ts > self.state.windows_cursor_unix {
                                self.state.windows_cursor_unix = event_ts;
                            }
                            continue;
                        }

                        let rule = windows_rule_for_event(&ev);
                        alerts.push(Alert::new(
                            rule,
                            &ev.severity,
                            format!("[{}:{}] {}", ev.source, ev.kind, ev.message),
                        ));
                        if event_ts > self.state.windows_cursor_unix {
                            self.state.windows_cursor_unix = event_ts;
                        }
                    }
                }
                Err(e) => alerts.push(Alert::new(
                    "windows_ingestion_failed",
                    "medium",
                    format!("Windows ingestion failed: {e}"),
                )),
            }
        }

        if self.config.memory_ingestion_enabled {
            match ingest_memory_events_since(
                self.state.memory_cursor_unix,
                &self.config.memory_event_log_path,
                self.config.memory_event_limit,
            ) {
                Ok(result) => {
                    if result.parse_errors > 0 {
                        alerts.push(Alert::new(
                            "memory_event_parse_failed",
                            "medium",
                            format!(
                                "Memory ingestion skipped {} malformed events",
                                result.parse_errors
                            ),
                        ));
                    }

                    for ev in result.events {
                        let event_ts = memory_event_ts(&ev, scan_ts);
                        if !self.should_emit_memory_event(&ev, event_ts) {
                            if event_ts > self.state.memory_cursor_unix {
                                self.state.memory_cursor_unix = event_ts;
                            }
                            continue;
                        }

                        match ev {
                            MemoryEventRecord::Injection {
                                source_pid,
                                source_image,
                                target_pid,
                                target_image,
                                technique_hint,
                                ..
                            } => {
                                let event = InjectionEvent {
                                    source_pid,
                                    source_image,
                                    target_pid,
                                    target_image,
                                    technique_hint,
                                    timestamp: unix_ts_to_system(event_ts),
                                };
                                let (alert, mem_alert) =
                                    self.memory_pipeline.handle_injection_event(event);
                                if let Some(client) = &self.backend_client {
                                    if let Err(e) = client.send_memory_alert(&mem_alert) {
                                        alerts.push(Alert::new(
                                            "backend_memory_alert_failed",
                                            "medium",
                                            format!("Backend memory alert failed: {e}"),
                                        ));
                                    }
                                }
                                alerts.push(alert);
                            }
                            MemoryEventRecord::MemProt {
                                pid,
                                process_image,
                                address,
                                size,
                                old_protection,
                                new_protection,
                                ..
                            } => {
                                let event = MemProtEvent {
                                    pid,
                                    process_image,
                                    address,
                                    size,
                                    old_protection,
                                    new_protection,
                                    timestamp: unix_ts_to_system(event_ts),
                                };
                                if let Some((alert, mem_alert)) =
                                    self.memory_pipeline.handle_memprot_event(event)
                                {
                                    if let Some(client) = &self.backend_client {
                                        if let Err(e) = client.send_memory_alert(&mem_alert) {
                                            alerts.push(Alert::new(
                                                "backend_memory_alert_failed",
                                                "medium",
                                                format!("Backend memory alert failed: {e}"),
                                            ));
                                        }
                                    }
                                    alerts.push(alert);
                                }
                            }
                            MemoryEventRecord::LsassAccess {
                                source_pid,
                                source_image,
                                access_mask,
                                ..
                            } => {
                                let event = LsassAccessEvent {
                                    source_pid,
                                    source_image,
                                    access_mask,
                                    timestamp: unix_ts_to_system(event_ts),
                                };
                                if let Some((alert, mem_alert)) =
                                    self.memory_pipeline.handle_lsass_access_event(event)
                                {
                                    if let Some(client) = &self.backend_client {
                                        if let Err(e) = client.send_memory_alert(&mem_alert) {
                                            alerts.push(Alert::new(
                                                "backend_memory_alert_failed",
                                                "medium",
                                                format!("Backend memory alert failed: {e}"),
                                            ));
                                        }
                                    }
                                    alerts.push(alert);
                                }
                            }
                        }

                        if event_ts > self.state.memory_cursor_unix {
                            self.state.memory_cursor_unix = event_ts;
                        }
                    }
                }
                Err(e) => alerts.push(Alert::new(
                    "memory_ingestion_failed",
                    "medium",
                    format!("Memory ingestion failed: {e}"),
                )),
            }
        }

        let mut effective_ioc = self.config.ioc.clone();
        let mut suspicious_ext = self.config.suspicious_file_extensions.clone();
        let mut response_profile = self.config.response_profile;
        let mut response_action_cooldown_seconds = self.config.response_action_cooldown_seconds;
        let mut response_allowlisted_process_names =
            self.config.response_allowlisted_process_names.clone();
        let mut response_allowlisted_process_paths =
            self.config.response_allowlisted_process_paths.clone();
        if self.config.enable_policy_reload {
            match load_policy(&self.config.policy_path) {
                Ok(pol) => {
                    effective_ioc
                        .blocked_process_names
                        .extend(pol.blocked_process_names);
                    effective_ioc
                        .blocked_command_substrings
                        .extend(pol.blocked_command_substrings);
                    effective_ioc
                        .blocked_remote_ips
                        .extend(pol.blocked_remote_ips);
                    effective_ioc
                        .blocked_remote_ports
                        .extend(pol.blocked_remote_ports);
                    suspicious_ext.extend(pol.suspicious_file_extensions);
                    response_allowlisted_process_names.extend(pol.response_allowlisted_process_names);
                    response_allowlisted_process_paths.extend(pol.response_allowlisted_process_paths);
                    if let Some(policy_response_profile) = pol.response_profile {
                        response_profile = policy_response_profile;
                    }
                    if let Some(policy_response_cooldown) = pol.response_action_cooldown_seconds {
                        response_action_cooldown_seconds = policy_response_cooldown;
                    }
                }
                Err(e) => alerts.push(Alert::new(
                    "policy_reload_failed",
                    "medium",
                    format!("Policy reload failed: {e}"),
                )),
            }
        }

        match collect_processes(&self.config.cpp_collector_path) {
            Ok(processes) => {
                alerts.extend(detect_suspicious_processes(&processes, &effective_ioc));
                let mut name_by_pid = HashMap::new();
                for proc in &processes {
                    name_by_pid.insert(proc.pid, proc.name.clone());
                }
                for proc in processes {
                    let parent_image = name_by_pid.get(&proc.ppid).cloned();
                    let event = ProcessEvent {
                        pid: proc.pid.max(0) as u32,
                        ppid: proc.ppid.max(0) as u32,
                        image_path: proc.name.clone(),
                        command_line: proc.command.clone(),
                        timestamp: SystemTime::now(),
                        parent_image,
                    };
                    alerts.extend(self.behavioral_pipeline.handle_process_event(event));
                }

                for pid in self.behavioral_pipeline.drain_memory_scan_triggers() {
                    alerts.push(Alert::with_pid(
                        "behavioral_memory_scan_trigger",
                        "high",
                        format!(
                            "High-risk process tree triggered on-demand memory scan for PID {}",
                            pid
                        ),
                        pid as i32,
                    ));

                    match self.memory_scanner.scan_pid_collect(pid) {
                        Ok(threats) => {
                            for threat in threats {
                                let severity = memory_threat_severity(&threat.severity).to_string();
                                let process_name = threat.process_name.clone();
                                let mut alert = Alert::with_pid(
                                    "memory_triggered_threat_detected",
                                    &severity,
                                    format!(
                                        "Triggered memory scan detected {:?} in process {} (PID {})",
                                        threat.threat_type, process_name, threat.pid
                                    ),
                                    threat.pid as i32,
                                );
                                alert.set_details(json!({
                                    "threat_type": format!("{:?}", threat.threat_type),
                                    "process_name": process_name,
                                    "address": threat.address,
                                    "size": threat.size,
                                    "protection": threat.protection,
                                    "indicators": threat.indicators,
                                    "mitre_attack": threat.mitre_attack,
                                }));
                                alerts.push(alert);

                                self.apply_memory_triggered_response(
                                    pid,
                                    &severity,
                                    &threat.process_name,
                                    scan_ts,
                                    response_profile,
                                    response_action_cooldown_seconds,
                                    &response_allowlisted_process_names,
                                    &response_allowlisted_process_paths,
                                    &mut alerts,
                                );
                            }
                        }
                        Err(e) => {
                            alerts.push(Alert::with_pid(
                                "memory_triggered_scan_failed",
                                "medium",
                                format!("Triggered memory scan failed for PID {}: {}", pid, e),
                                pid as i32,
                            ));
                        }
                    }
                }

                if matches!(ui_command, Some(UiCommandAction::MemoryScan)) {
                    match self.memory_scanner.scan_all_collect() {
                        Ok(threats) => {
                            let finding_count = threats.len();
                            for threat in threats {
                                let severity = memory_threat_severity(&threat.severity).to_string();
                                let mut alert = Alert::with_pid(
                                    "memory_on_demand_threat_detected",
                                    &severity,
                                    format!(
                                        "On-demand memory scan detected {:?} in process {} (PID {})",
                                        threat.threat_type, threat.process_name, threat.pid
                                    ),
                                    threat.pid as i32,
                                );
                                alert.set_details(json!({
                                    "threat_type": format!("{:?}", threat.threat_type),
                                    "process_name": threat.process_name,
                                    "address": threat.address,
                                    "size": threat.size,
                                    "protection": threat.protection,
                                    "indicators": threat.indicators,
                                    "mitre_attack": threat.mitre_attack,
                                    "source": "ui_memory_scan",
                                }));
                                alerts.push(alert);

                                self.apply_memory_triggered_response(
                                    threat.pid,
                                    &severity,
                                    &threat.process_name,
                                    scan_ts,
                                    response_profile,
                                    response_action_cooldown_seconds,
                                    &response_allowlisted_process_names,
                                    &response_allowlisted_process_paths,
                                    &mut alerts,
                                );
                            }
                            alerts.push(Alert::new(
                                "ui_memory_scan_completed",
                                "low",
                                format!("UI memory scan completed with {} findings", finding_count),
                            ));
                        }
                        Err(e) => alerts.push(Alert::new(
                            "ui_memory_scan_failed",
                            "medium",
                            format!("UI memory scan failed: {}", e),
                        )),
                    }
                    ui_command = None;
                }
            }
            Err(e) => alerts.push(Alert::new(
                "process_collection_failed",
                "high",
                format!("Process collection failed: {e}"),
            )),
        }

        match collect_network_connections() {
            Ok(connections) => {
                alerts.extend(detect_suspicious_connections(&connections, &effective_ioc))
            }
            Err(e) => alerts.push(Alert::new(
                "network_collection_failed",
                "medium",
                format!("Network collection failed: {e}"),
            )),
        }

        let mut current_hashes: HashMap<String, String> = HashMap::new();
        let mut excluded_paths = HashSet::new();
        for p in [
            &self.config.state_path,
            &self.config.alert_log_path,
            &self.config.incident_log_path,
            &self.config.telemetry_spool_path,
            &self.config.heartbeat_log_path,
            &self.config.ui_status_path,
            &self.config.ui_command_path,
            &self.config.policy_path,
            &self.config.kernel_event_log_path,
            &self.config.yara_rules_path,
        ] {
            if let Ok(c) = p.canonicalize() {
                excluded_paths.insert(c);
            }
        }

        for monitored_path in &self.config.monitored_directories {
            if !monitored_path.exists() {
                alerts.push(Alert::new(
                    "monitor_path_missing",
                    "medium",
                    format!("Monitored path missing: {}", monitored_path.display()),
                ));
                continue;
            }
            if !monitored_path.is_dir() {
                alerts.push(Alert::new(
                    "monitor_path_invalid",
                    "medium",
                    format!(
                        "Monitored path is not a directory: {}",
                        monitored_path.display()
                    ),
                ));
                continue;
            }

            let (snapshot, errors) = build_file_snapshot(
                monitored_path,
                &self.config.excluded_directory_names,
                &excluded_paths,
                &self.config.excluded_file_names,
            );
            current_hashes.extend(snapshot);
            for e in errors {
                alerts.push(Alert::new("file_collection_failed", "low", e));
            }
        }

        if self.config.auto_quarantine_suspicious_files && !suspicious_ext.is_empty() {
            let quarantine_alerts = quarantine_suspicious_files(
                &mut current_hashes,
                &suspicious_ext,
                &self.config.quarantine_dir,
            );
            alerts.extend(quarantine_alerts);
        }

        if !self.state.file_hashes.is_empty() || !self.config.initialize_baseline_without_alerting {
            alerts.extend(detect_file_changes(
                &self.state.file_hashes,
                &current_hashes,
            ));
            let change_summary = summarize_file_changes(&self.state.file_hashes, &current_hashes);
            if scan_ts.saturating_sub(self.state.ransomware_last_alert_ts)
                >= self.config.ransomware_alert_cooldown_seconds
            {
                if let Some(alert) = detect_ransomware_activity(
                    &self.state.file_hashes,
                    &current_hashes,
                    self.config.ransomware_change_threshold,
                    self.config.ransomware_delete_threshold,
                    &suspicious_ext,
                    self.config.ransomware_extension_threshold,
                    self.config.ransomware_sample_limit,
                ) {
                    alerts.push(alert);
                    self.state.ransomware_last_alert_ts = scan_ts;
                } else if let Some(alert) = detect_ransomware_note_files(
                    &self.state.file_hashes,
                    &current_hashes,
                    &self.config.ransomware_note_tokens,
                    self.config.ransomware_note_threshold,
                    self.config.ransomware_note_sample_limit,
                ) {
                    alerts.push(alert);
                    self.state.ransomware_last_alert_ts = scan_ts;
                }
            }

            let yara_alerts =
                self.scan_yara_matches(scan_ts, &change_summary.changed_paths, &suspicious_ext);
            alerts.extend(yara_alerts);

            if matches!(ui_command, Some(UiCommandAction::FullScan)) {
                let all_paths: Vec<String> = current_hashes.keys().cloned().collect();
                let full_scan_alerts = self.scan_yara_matches(scan_ts, &all_paths, &HashSet::new());
                let finding_count = full_scan_alerts.len();
                alerts.extend(full_scan_alerts);
                alerts.push(Alert::new(
                    "ui_full_scan_completed",
                    "low",
                    format!(
                        "UI full scan completed across {} files with {} findings",
                        all_paths.len(), finding_count
                    ),
                ));
                ui_command = None;
            }

            if matches!(ui_command, Some(UiCommandAction::QuickScan)) {
                alerts.push(Alert::new(
                    "ui_quick_scan_completed",
                    "low",
                    format!("UI quick scan completed with {} findings", alerts.len()),
                ));
                ui_command = None;
            }
        }

        normalize_alerts(&mut alerts);

        let incidents = correlate_incidents(&alerts, self.config.incident_risk_threshold, scan_ts);
        if !incidents.is_empty() {
            self.write_incidents(scan_ts, &incidents)?;
            for inc in &incidents {
                alerts.push(Alert::new(
                    "incident_correlated",
                    "critical",
                    format!(
                        "{} risk={} alerts={} pid={}",
                        inc.incident_id, inc.risk_score, inc.alert_count, inc.primary_pid
                    ),
                ));
            }
        }

        if self.config.auto_kill_on_high {
            for alert in &alerts {
                if (alert.severity == "high" || alert.severity == "critical") && alert.pid.is_some()
                {
                    let _ = kill_process(alert.pid.unwrap_or_default());
                }
            }
        }

        if self.state.kernel_cursor_unix == 0 {
            self.state.kernel_cursor_unix = scan_ts;
        }
        if self.config.windows_ingestion_enabled && self.state.windows_cursor_unix == 0 {
            self.state.windows_cursor_unix = scan_ts;
        }
        self.state.file_hashes = current_hashes;
        self.state.save(&self.config.state_path)?;

        if !alerts.is_empty() {
            self.write_alerts(scan_ts, &alerts)?;
        }

        let _ = write_heartbeat(
            &self.config.heartbeat_log_path,
            scan_ts,
            alerts.len(),
            incidents.len(),
        );

        let scan_end_ts = now_unix().unwrap_or(scan_ts);
        let scan_duration_ms = scan_start_instant.elapsed().as_millis() as u64;
        let _ = self.write_scan_status(
            scan_end_ts,
            &alerts,
            &incidents,
            "completed",
            scan_mode,
            scan_ts,
            Some(scan_end_ts),
            scan_duration_ms,
            "Scan completed",
        );

        if self.config.telemetry_enabled {
            if let Err(err) = publish_or_spool(
                &self.config.telemetry_endpoint,
                &self.config.telemetry_api_key,
                &self.config.telemetry_spool_path,
                &self.config.telemetry_tenant_id,
                &self.config.telemetry_endpoint_id,
                scan_ts,
                &alerts,
                &incidents,
            ) {
                let telemetry_alert = Alert::new(
                    "telemetry_publish_failed",
                    "medium",
                    format!("telemetry publish failed: {err}"),
                );
                self.write_alerts(scan_ts, &[telemetry_alert])?;
            }
        }

        Ok(alerts)
    }

    fn consume_ui_command(&self) -> Result<Option<UiCommandAction>, String> {
        if !self.config.ui_command_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.config.ui_command_path).map_err(|e| e.to_string())?;
        let payload: serde_json::Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        let action_raw = payload
            .get("action")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let target_path = payload
            .get("target_path")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let restore_to_original = payload
            .get("restore_to_original")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let _ = fs::remove_file(&self.config.ui_command_path);

        if action_raw.is_empty() {
            return Ok(None);
        }

        let action = match action_raw.as_str() {
            "quick_scan" | "quick" => UiCommandAction::QuickScan,
            "full_scan" | "full" => UiCommandAction::FullScan,
            "memory_scan" | "memory" => UiCommandAction::MemoryScan,
            "restore_quarantine" if !target_path.is_empty() => {
                UiCommandAction::RestoreQuarantine {
                    target_path,
                    restore_to_original,
                }
            }
            "delete_quarantine" if !target_path.is_empty() => {
                UiCommandAction::DeleteQuarantine { target_path }
            }
            other => UiCommandAction::Unknown(other.to_string()),
        };

        Ok(Some(action))
    }

    fn apply_memory_triggered_response(
        &mut self,
        pid: u32,
        severity: &str,
        process_name: &str,
        scan_ts: u64,
        response_profile: ResponseProfile,
        response_action_cooldown_seconds: u64,
        response_allowlisted_process_names: &HashSet<String>,
        response_allowlisted_process_paths: &HashSet<String>,
        alerts: &mut Vec<Alert>,
    ) {
        let is_high_or_critical = matches!(severity, "high" | "critical");
        if !is_high_or_critical {
            return;
        }

        if !response_profile.allows_containment() {
            alerts.push(Alert::with_pid(
                "response_skipped_profile_detect_only",
                "low",
                format!(
                    "Auto-response skipped for PID {} because response_profile=detect_only",
                    pid
                ),
                pid as i32,
            ));
            return;
        }

        let executable_path = resolve_process_executable_path(pid);
        if is_allowlisted_process(
            process_name,
            executable_path.as_deref(),
            response_allowlisted_process_names,
            response_allowlisted_process_paths,
        ) {
            alerts.push(Alert::with_pid(
                "response_skipped_allowlist",
                "low",
                format!(
                    "Auto-response skipped for PID {} because process is allowlisted",
                    pid
                ),
                pid as i32,
            ));
            return;
        }

        let action_key = format!("response:pid:{}", pid);
        if !self.record_response_action_if_allowed(
            &action_key,
            scan_ts,
            response_action_cooldown_seconds,
        ) {
            alerts.push(Alert::with_pid(
                "response_skipped_cooldown",
                "low",
                format!(
                    "Auto-response skipped for PID {} due to cooldown ({}s)",
                    pid, response_action_cooldown_seconds
                ),
                pid as i32,
            ));
            return;
        }

        if response_profile.allows_aggressive() && self.config.auto_kill_on_high {
            match kill_process(pid as i32) {
                Ok(()) => alerts.push(Alert::with_pid(
                    "response_process_terminated",
                    "high",
                    format!("Auto-response terminated PID {} after memory threat confirmation", pid),
                    pid as i32,
                )),
                Err(e) => alerts.push(Alert::with_pid(
                    "response_process_termination_failed",
                    "medium",
                    format!("Failed to terminate PID {}: {}", pid, e),
                    pid as i32,
                )),
            }
        }

        if self.config.auto_quarantine_suspicious_files {
            if let Some(path) = executable_path {
                match quarantine_file_with_metadata(
                    &path,
                    &self.config.quarantine_dir,
                    "memory_triggered_response",
                    None,
                ) {
                    Ok(target) => alerts.push(Alert::with_pid(
                        "response_file_quarantined",
                        "high",
                        format!(
                            "Auto-response quarantined executable for PID {} to {}",
                            pid,
                            target.display()
                        ),
                        pid as i32,
                    )),
                    Err(e) => alerts.push(Alert::with_pid(
                        "response_file_quarantine_failed",
                        "medium",
                        format!(
                            "Failed to quarantine executable for PID {} at {}: {}",
                            pid, path, e
                        ),
                        pid as i32,
                    )),
                }
            } else {
                alerts.push(Alert::with_pid(
                    "response_file_path_unresolved",
                    "low",
                    format!(
                        "Could not resolve executable path for PID {} during auto-quarantine",
                        pid
                    ),
                    pid as i32,
                ));
            }
        }
    }

    fn record_response_action_if_allowed(&mut self, key: &str, now_ts: u64, cooldown: u64) -> bool {
        if let Some(last_ts) = self.response_action_recent.get(key).copied() {
            if now_ts.saturating_sub(last_ts) < cooldown {
                return false;
            }
        }
        self.response_action_recent.insert(key.to_string(), now_ts);
        true
    }

    pub fn run_forever(&mut self) -> Result<(), String> {
        loop {
            self.scan_once()?;
            thread::sleep(Duration::from_secs(self.config.scan_interval_seconds));
        }
    }

    fn write_scan_status(
        &self,
        ts: u64,
        alerts: &[Alert],
        incidents: &[crate::models::Incident],
        scan_state: &str,
        scan_mode: &str,
        started_at_unix: u64,
        completed_at_unix: Option<u64>,
        duration_ms: u64,
        lifecycle_message: &str,
    ) -> Result<(), String> {
        if let Some(parent) = self.config.ui_status_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }

        let quarantine_file_count = fs::read_dir(&self.config.quarantine_dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().is_file())
                    .count()
            })
            .unwrap_or(0);

        let payload = json!({
            "timestamp_unix": ts,
            "alert_count": alerts.len(),
            "incident_count": incidents.len(),
            "highest_severity": highest_alert_severity(alerts),
            "scan_lifecycle": {
                "state": scan_state,
                "mode": scan_mode,
                "started_at_unix": started_at_unix,
                "completed_at_unix": completed_at_unix,
                "duration_ms": duration_ms,
                "message": lifecycle_message,
                "progress_percent": if scan_state == "running" { 15 } else { 100 },
            },
            "quarantine": {
                "path": self.config.quarantine_dir,
                "file_count": quarantine_file_count,
            },
            "alerts": alerts.iter().take(200).map(alert_to_json).collect::<Vec<_>>(),
            "incidents": incidents.iter().take(50).map(|incident| {
                json!({
                    "incident_id": incident.incident_id,
                    "primary_pid": incident.primary_pid,
                    "risk_score": incident.risk_score,
                    "alert_count": incident.alert_count,
                    "summary": incident.summary,
                })
            }).collect::<Vec<_>>(),
        });

        fs::write(
            &self.config.ui_status_path,
            serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }

    fn write_alerts(&self, ts: u64, alerts: &[Alert]) -> Result<(), String> {
        if let Some(parent) = self.config.alert_log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.alert_log_path)
            .map_err(|e| e.to_string())?;
        for alert in alerts {
            writeln!(f, "{} {}", ts, alert.serialize()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn write_incidents(
        &self,
        ts: u64,
        incidents: &[crate::models::Incident],
    ) -> Result<(), String> {
        if let Some(parent) = self.config.incident_log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.incident_log_path)
            .map_err(|e| e.to_string())?;
        for incident in incidents {
            writeln!(f, "{}", incident.to_json_line(ts)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn should_emit_kernel_event(
        &mut self,
        event: &crate::ingestion::SensorEvent,
        event_ts: u64,
    ) -> bool {
        let cutoff = event_ts.saturating_sub(self.config.kernel_dedupe_window_seconds);
        self.kernel_event_recent
            .retain(|_, seen_ts| *seen_ts >= cutoff);

        let key = format!(
            "{}|{}|{}",
            event.source,
            event.kind,
            event.message.to_lowercase()
        );
        if let Some(last_seen) = self.kernel_event_recent.get(&key) {
            if *last_seen >= cutoff {
                return false;
            }
        }
        self.kernel_event_recent.insert(key, event_ts);
        true
    }

    fn should_emit_windows_event(
        &mut self,
        event: &crate::ingestion::SensorEvent,
        event_ts: u64,
    ) -> bool {
        let cutoff = event_ts.saturating_sub(self.config.windows_dedupe_window_seconds);
        self.windows_event_recent
            .retain(|_, seen_ts| *seen_ts >= cutoff);

        let key = format!(
            "{}|{}|{}",
            event.source,
            event.kind,
            event.message.to_lowercase()
        );
        if let Some(last_seen) = self.windows_event_recent.get(&key) {
            if *last_seen >= cutoff {
                return false;
            }
        }
        self.windows_event_recent.insert(key, event_ts);
        true
    }

    fn should_emit_memory_event(&mut self, event: &MemoryEventRecord, event_ts: u64) -> bool {
        let cutoff = event_ts.saturating_sub(self.config.memory_dedupe_window_seconds);
        self.memory_event_recent
            .retain(|_, seen_ts| *seen_ts >= cutoff);

        let key = match event {
            MemoryEventRecord::Injection {
                source_pid,
                target_pid,
                technique_hint,
                ..
            } => format!("inj|{source_pid}|{target_pid}|{technique_hint:?}"),
            MemoryEventRecord::MemProt {
                pid,
                address,
                new_protection,
                ..
            } => format!("memprot|{pid}|{address:X}|{new_protection:X}"),
            MemoryEventRecord::LsassAccess {
                source_pid,
                access_mask,
                ..
            } => format!("lsass|{source_pid}|{access_mask:X}"),
        };

        if let Some(last_seen) = self.memory_event_recent.get(&key) {
            if *last_seen >= cutoff {
                return false;
            }
        }
        self.memory_event_recent.insert(key, event_ts);
        true
    }

    fn write_kernel_events(
        &self,
        events: &[(crate::ingestion::SensorEvent, u64)],
    ) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.config.kernel_event_log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.kernel_event_log_path)
            .map_err(|e| e.to_string())?;
        for (event, event_ts) in events {
            writeln!(
                f,
                "{{\"ts\":{},\"source\":\"{}\",\"kind\":\"{}\",\"severity\":\"{}\",\"message\":\"{}\"}}",
                event_ts,
                escape_json(&event.source),
                escape_json(&event.kind),
                escape_json(&event.severity),
                escape_json(&event.message)
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn write_windows_events(
        &self,
        events: &[(crate::ingestion::SensorEvent, u64)],
    ) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.config.windows_event_log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.windows_event_log_path)
            .map_err(|e| e.to_string())?;
        for (event, event_ts) in events {
            writeln!(
                f,
                "{{\"ts\":{},\"source\":\"{}\",\"kind\":\"{}\",\"severity\":\"{}\",\"message\":\"{}\"}}",
                event_ts,
                escape_json(&event.source),
                escape_json(&event.kind),
                escape_json(&event.severity),
                escape_json(&event.message)
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn refresh_yara_rules(&mut self, scan_ts: u64) -> Result<(), String> {
        if self.config.yara_rules_url.trim().is_empty() {
            return Ok(());
        }
        if scan_ts.saturating_sub(self.state.yara_last_fetch_ts)
            < self.config.yara_poll_interval_seconds
        {
            return Ok(());
        }

        if let Some(parent) = self.config.yara_rules_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp_path = self.config.yara_rules_path.with_extension("tmp");
        let mut args = vec![
            "-fsSL".to_string(),
            self.config.yara_rules_url.clone(),
            "-o".to_string(),
            tmp_path
                .to_str()
                .ok_or("invalid yara rules temp path")?
                .to_string(),
        ];
        if self.config.yara_rules_path.exists() {
            args.insert(2, self.config.yara_rules_path.to_string_lossy().to_string());
            args.insert(2, "-z".to_string());
        }
        let output = Command::new("curl")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(format!("curl failed: {stderr}"));
        }
        if should_replace_yara_rules(&tmp_path)? {
            fs::rename(&tmp_path, &self.config.yara_rules_path).map_err(|e| e.to_string())?;
        } else if tmp_path.exists() {
            fs::remove_file(&tmp_path).map_err(|e| e.to_string())?;
        }
        self.state.yara_last_fetch_ts = scan_ts;
        Ok(())
    }

    fn scan_yara_matches(
        &mut self,
        scan_ts: u64,
        paths: &[String],
        suspicious_ext: &HashSet<String>,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();
        if paths.is_empty() {
            return alerts;
        }
        if !self.config.yara_rules_path.exists() {
            return alerts;
        }
        let cooldown = self.config.yara_match_cooldown_seconds;
        self.yara_recent_matches
            .retain(|_, last_seen| scan_ts.saturating_sub(*last_seen) < cooldown);
        let limit = self.config.yara_scan_limit.min(paths.len());
        let mut skipped_large = 0;
        let mut skipped_meta = 0;
        let mut skipped_non_file = 0;
        for path in paths.iter().take(limit) {
            if self.config.yara_scan_only_suspicious_ext
                && !should_scan_yara_path(path, suspicious_ext)
            {
                continue;
            }
            let meta = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => {
                    skipped_meta += 1;
                    continue;
                }
            };
            if !meta.is_file() {
                skipped_non_file += 1;
                continue;
            }
            if !is_within_yara_size_limit(meta.len(), self.config.yara_max_file_size_bytes) {
                skipped_large += 1;
                continue;
            }

            let output = Command::new("yara")
                .args([
                    "-r",
                    self.config.yara_rules_path.to_str().unwrap_or_default(),
                    path,
                ])
                .output();
            let output = match output {
                Ok(o) => o,
                Err(_) => {
                    alerts.push(Alert::new(
                        "yara_scan_failed",
                        "medium",
                        "yara binary not available for scanning".to_string(),
                    ));
                    break;
                }
            };
            if output.status.code() == Some(1) {
                let matches = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let message = if matches.is_empty() {
                    format!("Yara match detected for {}", path)
                } else {
                    format!("Yara match detected: {} ({})", matches, path)
                };
                let key = format!("{}|{}", matches, path);
                if should_emit_yara_match(
                    self.yara_recent_matches.get(&key).copied(),
                    scan_ts,
                    cooldown,
                ) {
                    alerts.push(Alert::new("yara_match_detected", "high", message));
                    self.yara_recent_matches.insert(key, scan_ts);
                    if self.config.auto_quarantine_yara_matches {
                        if let Err(err) = quarantine_file_with_metadata(
                            path,
                            &self.config.quarantine_dir,
                            "yara_match",
                            None,
                        ) {
                            alerts.push(Alert::new(
                                "yara_quarantine_failed",
                                "medium",
                                format!("yara quarantine failed for {}: {err}", path),
                            ));
                        } else {
                            alerts.push(Alert::new(
                                "yara_file_quarantined",
                                "high",
                                format!(
                                    "Quarantined Yara match {} to {}",
                                    path,
                                    self.config.quarantine_dir.display()
                                ),
                            ));
                        }
                    }
                }
            } else if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                alerts.push(Alert::new(
                    "yara_scan_failed",
                    "medium",
                    format!("yara scan failed for {}: {}", path, stderr),
                ));
            }
        }
        if skipped_large > 0 || skipped_meta > 0 || skipped_non_file > 0 {
            alerts.push(Alert::new(
                "yara_scan_skipped",
                "low",
                format!(
                    "Yara scan skipped files: oversized={} metadata_failed={} non_files={}",
                    skipped_large, skipped_meta, skipped_non_file
                ),
            ));
        }
        alerts
    }
}

fn scan_mode_from_command(command: Option<&UiCommandAction>) -> &'static str {
    match command {
        Some(UiCommandAction::QuickScan) => "quick_scan",
        Some(UiCommandAction::FullScan) => "full_scan",
        Some(UiCommandAction::MemoryScan) => "memory_scan",
        Some(UiCommandAction::RestoreQuarantine {
            restore_to_original: true,
            ..
        }) => "quarantine_restore_original",
        Some(UiCommandAction::RestoreQuarantine {
            restore_to_original: false,
            ..
        }) => "quarantine_restore_folder",
        Some(UiCommandAction::DeleteQuarantine { .. }) => "quarantine_delete",
        Some(UiCommandAction::Unknown(_)) => "unknown_command_scan",
        None => "scheduled",
    }
}

fn quarantine_suspicious_files(
    current_hashes: &mut HashMap<String, String>,
    suspicious_ext: &HashSet<String>,
    quarantine_dir: &Path,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let keys: Vec<String> = current_hashes.keys().cloned().collect();

    for path_s in keys {
        let path = PathBuf::from(&path_s);
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));

        if let Some(ext) = ext {
            if suspicious_ext.contains(&ext) {
                let source_hash = current_hashes.get(&path_s).cloned();
                match quarantine_file_with_metadata(
                    &path_s,
                    quarantine_dir,
                    "suspicious_extension",
                    source_hash.as_deref(),
                ) {
                    Ok(target) => {
                        current_hashes.remove(&path_s);
                        alerts.push(Alert::new(
                            "suspicious_file_quarantined",
                            "high",
                            format!(
                                "Quarantined suspicious file {} to {}",
                                path.display(),
                                target.display()
                            ),
                        ));
                    }
                    Err(e) => alerts.push(Alert::new(
                        "quarantine_failed",
                        "medium",
                        format!("quarantine failed for {}: {e}", path.display()),
                    )),
                }
            }
        }
    }

    alerts
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .map(|d| d.as_secs())
}

struct AgentFimReporter {
    alert_log_path: PathBuf,
    telemetry_enabled: bool,
    telemetry_endpoint: String,
    telemetry_api_key: String,
    telemetry_spool_path: PathBuf,
    telemetry_tenant_id: String,
    telemetry_endpoint_id: String,
    fim_baseline_path: PathBuf,
    backend_client: Option<Arc<BackendClient>>,
}

#[async_trait::async_trait]
impl FIMReporter for AgentFimReporter {
    async fn report_violation(&self, violation: FIMViolation) -> Result<()> {
        let severity = match violation.violation_type {
            FIMViolationType::HashMismatch | FIMViolationType::SizeChange => "high",
            FIMViolationType::UnauthorizedDeletion | FIMViolationType::UnauthorizedCreation => {
                "critical"
            }
            FIMViolationType::PermissionChange | FIMViolationType::OwnershipChange => "medium",
        };
        let message = format!(
            "FIM violation {:?} at {} (expected={}, actual={})",
            violation.violation_type,
            violation.path.display(),
            violation.expected_hash.as_deref().unwrap_or("unknown"),
            violation.actual_hash.as_deref().unwrap_or("missing")
        );
        let mut alert = Alert::new("fim_violation", severity, message);
        alert.set_details(json!({
            "path": violation.path.display().to_string(),
            "violation_type": format!("{:?}", violation.violation_type),
            "expected_hash": violation.expected_hash,
            "actual_hash": violation.actual_hash,
            "detected_at_unix": system_time_to_unix(violation.detected_at),
        }));

        let alert_log_path = self.alert_log_path.clone();
        let telemetry_enabled = self.telemetry_enabled;
        let telemetry_endpoint = self.telemetry_endpoint.clone();
        let telemetry_api_key = self.telemetry_api_key.clone();
        let telemetry_spool_path = self.telemetry_spool_path.clone();
        let telemetry_tenant_id = self.telemetry_tenant_id.clone();
        let telemetry_endpoint_id = self.telemetry_endpoint_id.clone();
        let backend_client = self.backend_client.clone();
        let violation_snapshot = violation.clone();

        tokio::task::spawn_blocking(move || {
            let ts = now_unix().map_err(|e| anyhow::anyhow!(e))?;
            if let Some(parent) = alert_log_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| anyhow::anyhow!(e))?;
            }
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&alert_log_path)
                .map_err(|e| anyhow::anyhow!(e))?;
            writeln!(f, "{} {}", ts, alert.serialize()).map_err(|e| anyhow::anyhow!(e))?;

            if telemetry_enabled {
                let _ = publish_or_spool(
                    &telemetry_endpoint,
                    &telemetry_api_key,
                    &telemetry_spool_path,
                    &telemetry_tenant_id,
                    &telemetry_endpoint_id,
                    ts,
                    &[alert],
                    &[],
                );
            }
            if let Some(client) = backend_client {
                let _ = client.send_fim_violation(&violation_snapshot);
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    async fn sync_baseline(
        &self,
        baseline: &HashMap<PathBuf, crate::fim_engine::FileBaseline>,
    ) -> Result<()> {
        let baseline_path = self.fim_baseline_path.clone();
        let snapshot = baseline.clone();
        let backend_client = self.backend_client.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = baseline_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| anyhow::anyhow!(e))?;
            }
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&baseline_path)
                .map_err(|e| anyhow::anyhow!(e))?;
            for (path, entry) in &snapshot {
                let mtime = entry
                    .modified_time
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let baseline_ts = entry
                    .baseline_timestamp
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                writeln!(
                    f,
                    "{}\t{}\t{}\t{}\t{}",
                    path.display(),
                    entry.sha256_hash,
                    entry.size,
                    mtime,
                    baseline_ts
                )
                .map_err(|e| anyhow::anyhow!(e))?;
            }
            if let Some(client) = backend_client {
                let _ = client.sync_fim_baseline(&snapshot);
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }
}

fn start_fim_worker(
    config: &AgentConfig,
    backend_client: Option<Arc<BackendClient>>,
) -> Result<Option<thread::JoinHandle<()>>, String> {
    if !config.fim_enabled {
        return Ok(None);
    }

    let fim_config = FIMConfig {
        enabled: config.fim_enabled,
        scan_interval: Duration::from_secs(config.fim_scan_interval_seconds),
        monitored_paths: config.fim_monitored_paths.clone(),
        excluded_extensions: config.fim_excluded_extensions.iter().cloned().collect(),
    };

    let reporter = Arc::new(AgentFimReporter {
        alert_log_path: config.alert_log_path.clone(),
        telemetry_enabled: config.telemetry_enabled,
        telemetry_endpoint: config.telemetry_endpoint.clone(),
        telemetry_api_key: config.telemetry_api_key.clone(),
        telemetry_spool_path: config.telemetry_spool_path.clone(),
        telemetry_tenant_id: config.telemetry_tenant_id.clone(),
        telemetry_endpoint_id: config.telemetry_endpoint_id.clone(),
        fim_baseline_path: config.fim_baseline_path.clone(),
        backend_client,
    });

    let handle = thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("FIM runtime initialization failed: {e}");
                return;
            }
        };

        runtime.block_on(async move {
            let engine = Arc::new(FIMEngine::new(fim_config, reporter));
            if let Err(e) = engine.establish_baseline().await {
                eprintln!("FIM baseline failed: {e:#}");
            }
            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                if let Err(e) = engine_clone.run_continuous_validation().await {
                    eprintln!("FIM validation loop terminated: {e:#}");
                }
            });

            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    });

    Ok(Some(handle))
}

fn kill_process(pid: i32) -> Result<(), String> {
    let output = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn effective_kernel_ts(event: &crate::ingestion::SensorEvent, scan_ts: u64) -> u64 {
    if event.ts_unix == 0 {
        scan_ts
    } else {
        event.ts_unix
    }
}

fn memory_event_ts(event: &MemoryEventRecord, scan_ts: u64) -> u64 {
    let ts = match event {
        MemoryEventRecord::Injection { ts_unix, .. } => *ts_unix,
        MemoryEventRecord::MemProt { ts_unix, .. } => *ts_unix,
        MemoryEventRecord::LsassAccess { ts_unix, .. } => *ts_unix,
    };
    if ts == 0 {
        scan_ts
    } else {
        ts
    }
}

fn unix_ts_to_system(ts: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ts)
}

fn system_time_to_unix(ts: SystemTime) -> Option<u64> {
    ts.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn processing_kernel_ts(
    event: &crate::ingestion::SensorEvent,
    scan_ts: u64,
    kernel_cursor_unix: u64,
) -> u64 {
    effective_kernel_ts(event, scan_ts).max(kernel_cursor_unix.saturating_add(1))
}

fn is_within_yara_size_limit(size: u64, limit: u64) -> bool {
    size <= limit
}

fn should_emit_yara_match(last_seen: Option<u64>, scan_ts: u64, cooldown: u64) -> bool {
    match last_seen {
        Some(ts) => scan_ts.saturating_sub(ts) >= cooldown,
        None => true,
    }
}

fn highest_alert_severity(alerts: &[Alert]) -> &'static str {
    let mut max_weight = 0u32;
    for alert in alerts {
        max_weight = max_weight.max(alert.severity_weight());
    }

    match max_weight {
        10.. => "critical",
        7..=9 => "high",
        4..=6 => "medium",
        1..=3 => "low",
        _ => "none",
    }
}

fn ui_command_name(command: &UiCommandAction) -> String {
    match command {
        UiCommandAction::QuickScan => "quick_scan".to_string(),
        UiCommandAction::FullScan => "full_scan".to_string(),
        UiCommandAction::MemoryScan => "memory_scan".to_string(),
        UiCommandAction::RestoreQuarantine {
            target_path,
            restore_to_original,
        } => {
            format!(
                "restore_quarantine:{}:{}",
                if *restore_to_original {
                    "original"
                } else {
                    "restored"
                },
                target_path
            )
        }
        UiCommandAction::DeleteQuarantine { target_path } => {
            format!("delete_quarantine:{}", target_path)
        }
        UiCommandAction::Unknown(value) => format!("unknown:{}", value),
    }
}

fn alert_to_json(alert: &Alert) -> serde_json::Value {
    json!({
        "rule": alert.rule,
        "severity": alert.severity,
        "message": alert.message,
        "pid": alert.pid,
        "attack_tactic": alert.attack_tactic,
        "attack_technique": alert.attack_technique,
        "intel_tags": alert.intel_tags,
        "details": alert.details,
    })
}

fn should_scan_yara_path(path: &str, suspicious_ext: &HashSet<String>) -> bool {
    if suspicious_ext.is_empty() {
        return true;
    }
    Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .map_or(false, |ext| suspicious_ext.contains(&ext))
}

fn is_allowlisted_process(
    process_name: &str,
    executable_path: Option<&str>,
    allowlisted_process_names: &HashSet<String>,
    allowlisted_process_paths: &HashSet<String>,
) -> bool {
    let process_name_lc = process_name.to_lowercase();
    if allowlisted_process_names.contains(&process_name_lc) {
        return true;
    }

    let process_basename_lc = Path::new(process_name)
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase());
    if let Some(base_name) = process_basename_lc {
        if allowlisted_process_names.contains(&base_name) {
            return true;
        }
    }

    if let Some(path) = executable_path {
        let path_lc = path.to_lowercase();
        if allowlisted_process_paths.contains(&path_lc) {
            return true;
        }
        if let Some(base_name) = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().to_lowercase())
        {
            if allowlisted_process_names.contains(&base_name) {
                return true;
            }
        }
    }

    false
}

fn should_replace_yara_rules(tmp_path: &Path) -> Result<bool, String> {
    if !tmp_path.exists() {
        return Ok(false);
    }
    let meta = fs::metadata(tmp_path).map_err(|e| e.to_string())?;
    Ok(meta.len() > 0)
}

fn windows_rule_for_event(event: &crate::ingestion::SensorEvent) -> &'static str {
    let event_id = event
        .kind
        .strip_prefix("windows_event:")
        .and_then(|id| id.parse::<u32>().ok());
    match event_id {
        Some(1) | Some(4688) => "windows_process_start",
        Some(5) | Some(4689) => "windows_process_stop",
        Some(3) => "windows_network_connect",
        Some(11) => "windows_file_create",
        _ => "windows_event_signal",
    }
}

fn quarantine_file(path: &str, quarantine_dir: &Path) -> Result<(), String> {
    quarantine_file_with_metadata(path, quarantine_dir, "manual", None).map(|_| ())
}

fn quarantine_file_with_metadata(
    path: &str,
    quarantine_dir: &Path,
    reason: &str,
    source_hash: Option<&str>,
) -> Result<PathBuf, String> {
    fs::create_dir_all(quarantine_dir).map_err(|e| e.to_string())?;
    let source_path = Path::new(path);
    let file_name = source_path
        .file_name()
        .ok_or("missing file name for quarantine")?;
    let target = unique_quarantine_target_path(quarantine_dir, &file_name.to_string_lossy());
    match fs::rename(path, &target) {
        Ok(()) => {
            write_quarantine_metadata(&target, source_path, reason, source_hash)?;
            Ok(target)
        }
        Err(_) => {
            fs::copy(path, &target).map_err(|e| e.to_string())?;
            fs::remove_file(path).map_err(|e| e.to_string())?;
            write_quarantine_metadata(&target, source_path, reason, source_hash)?;
            Ok(target)
        }
    }
}

fn delete_quarantined_file(target_path: &str, quarantine_dir: &Path) -> Result<(), String> {
    let target = validate_quarantine_target_path(target_path, quarantine_dir)?;
    fs::remove_file(&target).map_err(|e| e.to_string())?;
    let sidecar = quarantine_sidecar_path(&target);
    if sidecar.exists() {
        let _ = fs::remove_file(sidecar);
    }
    Ok(())
}

fn restore_quarantined_file(
    target_path: &str,
    quarantine_dir: &Path,
    restore_to_original: bool,
) -> Result<PathBuf, String> {
    let target = validate_quarantine_target_path(target_path, quarantine_dir)?;
    let file_name = target
        .file_name()
        .ok_or("invalid quarantine target file name")?
        .to_string_lossy()
        .to_string();
    let sidecar = quarantine_sidecar_path(&target);

    let metadata_original_path = read_quarantine_original_path(&sidecar);
    let canonical_quarantine = quarantine_dir.canonicalize().map_err(|e| e.to_string())?;

    let preferred_destination = if restore_to_original {
        metadata_original_path
            .and_then(|candidate| {
                if candidate.as_os_str().is_empty() {
                    return None;
                }
                Some(candidate)
            })
            .filter(|candidate| {
                if let Ok(parent) = candidate
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .canonicalize()
                {
                    !parent.starts_with(&canonical_quarantine)
                } else {
                    true
                }
            })
    } else {
        None
    };

    let restore_dir = quarantine_dir.join("restored");
    let restore_path = if let Some(path) = preferred_destination {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        unique_restore_path(path)
    } else {
        fs::create_dir_all(&restore_dir).map_err(|e| e.to_string())?;
        unique_restore_path(restore_dir.join(file_name))
    };

    match fs::rename(&target, &restore_path) {
        Ok(()) => {}
        Err(_) => {
            fs::copy(&target, &restore_path).map_err(|e| e.to_string())?;
            fs::remove_file(&target).map_err(|e| e.to_string())?;
        }
    }

    if sidecar.exists() {
        let _ = fs::remove_file(sidecar);
    }

    Ok(restore_path)
}

fn read_quarantine_original_path(sidecar_path: &Path) -> Option<PathBuf> {
    let content = fs::read_to_string(sidecar_path).ok()?;
    let value = serde_json::from_str::<Value>(&content).ok()?;
    let original = value.get("original_path")?.as_str()?.trim();
    if original.is_empty() {
        return None;
    }
    Some(PathBuf::from(original))
}

fn write_quarantine_metadata(
    quarantined_path: &Path,
    original_path: &Path,
    reason: &str,
    source_hash: Option<&str>,
) -> Result<(), String> {
    let payload = json!({
        "original_path": original_path.to_string_lossy(),
        "quarantined_path": quarantined_path.to_string_lossy(),
        "reason": reason,
        "source_hash": source_hash,
        "quarantined_at_unix": now_unix().unwrap_or(0),
    });
    let sidecar = quarantine_sidecar_path(quarantined_path);
    fs::write(
        sidecar,
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn quarantine_sidecar_path(quarantined_path: &Path) -> PathBuf {
    let file_name = quarantined_path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "quarantined_file".to_string());
    quarantined_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{}.quarantine.json", file_name))
}

fn unique_quarantine_target_path(quarantine_dir: &Path, file_name: &str) -> PathBuf {
    unique_restore_path(quarantine_dir.join(file_name))
}

fn validate_quarantine_target_path(target_path: &str, quarantine_dir: &Path) -> Result<PathBuf, String> {
    let target = PathBuf::from(target_path);
    if !target.exists() {
        return Err("target does not exist".to_string());
    }
    if !target.is_file() {
        return Err("target is not a file".to_string());
    }

    let canonical_quarantine = quarantine_dir.canonicalize().map_err(|e| e.to_string())?;
    let canonical_target = target.canonicalize().map_err(|e| e.to_string())?;
    if !canonical_target.starts_with(&canonical_quarantine) {
        return Err("target path is outside quarantine directory".to_string());
    }

    Ok(canonical_target)
}

fn unique_restore_path(base_path: PathBuf) -> PathBuf {
    let base = base_path.as_path();
    let stem = base
        .file_stem()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "restored".to_string());
    let extension = base
        .extension()
        .map(|v| v.to_string_lossy().to_string());

    let parent_dir = base
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut candidate = base_path;
    if !candidate.exists() {
        return candidate;
    }

    let suffix = now_unix().unwrap_or(0);
    let mut i = 0u32;
    loop {
        let mut name = format!("{}_{}", stem, suffix + i as u64);
        if let Some(ext) = &extension {
            name.push('.');
            name.push_str(ext);
        }
        candidate = parent_dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
        i = i.saturating_add(1);
    }
}

fn resolve_process_executable_path(pid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let command = format!(
            "(Get-Process -Id {} -ErrorAction SilentlyContinue).Path",
            pid
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &command])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            return None;
        }
        return Some(path);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let proc_exe = format!("/proc/{}/exe", pid);
        if let Ok(path) = fs::read_link(&proc_exe) {
            return Some(path.to_string_lossy().to_string());
        }
        None
    }
}

fn memory_threat_severity(severity: &MemoryThreatSeverity) -> &'static str {
    match severity {
        MemoryThreatSeverity::Low => "low",
        MemoryThreatSeverity::Medium => "medium",
        MemoryThreatSeverity::High => "high",
        MemoryThreatSeverity::Critical => "critical",
    }
}

fn build_processed_kernel_events(
    events: Vec<crate::ingestion::SensorEvent>,
    scan_ts: u64,
    initial_cursor_unix: u64,
) -> Vec<(crate::ingestion::SensorEvent, u64)> {
    let mut cursor = initial_cursor_unix;
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        let event_ts = processing_kernel_ts(&event, scan_ts, cursor);
        cursor = cursor.max(event_ts);
        out.push((event, event_ts));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::SensorEvent;

    #[test]
    fn dedupe_window_suppresses_duplicate_kernel_events() {
        let mut agent = EdrAgent {
            config: AgentConfig {
                scan_interval_seconds: 1,
                alert_log_path: PathBuf::from("alerts.log"),
                state_path: PathBuf::from("state.db"),
                monitored_directories: vec![PathBuf::from(".")],
                excluded_directory_names: HashSet::new(),
                excluded_file_names: HashSet::new(),
                ioc: crate::config::IocConfig {
                    blocked_process_names: HashSet::new(),
                    blocked_command_substrings: HashSet::new(),
                    blocked_remote_ips: HashSet::new(),
                    blocked_remote_ports: HashSet::new(),
                },
                run_once: true,
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
                kernel_ingestion_enabled: true,
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
            },
            state: AgentState {
                file_hashes: HashMap::new(),
                kernel_cursor_unix: 0,
                windows_cursor_unix: 0,
                memory_cursor_unix: 0,
                ransomware_last_alert_ts: 0,
                yara_last_fetch_ts: 0,
            },
            kernel_event_recent: HashMap::new(),
            windows_event_recent: HashMap::new(),
            yara_recent_matches: HashMap::new(),
            memory_event_recent: HashMap::new(),
            response_action_recent: HashMap::new(),
            memory_pipeline: MemoryPipeline::new(),
            memory_scanner: MemoryScanner::new(),
            behavioral_pipeline: BehavioralPipeline::new(),
            fim_handle: None,
            backend_client: None,
        };

        let event = SensorEvent {
            ts_unix: 100,
            source: "journalctl".to_string(),
            kind: "kernel_panic".to_string(),
            severity: "critical".to_string(),
            message: "panic happened".to_string(),
        };

        assert!(agent.should_emit_kernel_event(&event, 100));
        assert!(!agent.should_emit_kernel_event(&event, 100));

        let later = SensorEvent {
            ts_unix: 500,
            ..event
        };
        assert!(agent.should_emit_kernel_event(&later, 500));
    }

    #[test]
    fn zero_kernel_timestamp_uses_scan_time() {
        let event = SensorEvent {
            ts_unix: 0,
            source: "dmesg".to_string(),
            kind: "kernel_signal".to_string(),
            severity: "low".to_string(),
            message: "oom killer invoked".to_string(),
        };
        assert_eq!(effective_kernel_ts(&event, 42), 42);
    }

    #[test]
    fn processing_timestamp_is_monotonic_against_cursor() {
        let event = SensorEvent {
            ts_unix: 100,
            source: "journalctl".to_string(),
            kind: "kernel_signal".to_string(),
            severity: "low".to_string(),
            message: "old event replayed".to_string(),
        };

        assert_eq!(processing_kernel_ts(&event, 1000, 1200), 1201);
    }

    #[test]
    fn yara_size_limit_allows_small_files() {
        assert!(is_within_yara_size_limit(10, 100));
        assert!(!is_within_yara_size_limit(200, 100));
    }

    #[test]
    fn yara_match_cooldown_blocks_duplicates() {
        assert!(should_emit_yara_match(None, 100, 300));
        assert!(!should_emit_yara_match(Some(50), 100, 300));
        assert!(should_emit_yara_match(Some(50), 400, 300));
    }

    #[test]
    fn yara_scan_filters_to_suspicious_extensions() {
        let mut exts = HashSet::new();
        exts.insert(".locked".to_string());
        assert!(should_scan_yara_path("sample.locked", &exts));
        assert!(!should_scan_yara_path("sample.txt", &exts));
        assert!(should_scan_yara_path("sample.txt", &HashSet::new()));
    }

    #[test]
    fn yara_rules_replace_requires_non_empty_tmp() {
        let dir = std::env::temp_dir();
        let tmp = dir.join("yara_rules_test.tmp");
        std::fs::write(&tmp, "").expect("write tmp");
        assert!(!should_replace_yara_rules(&tmp).expect("check tmp"));
        std::fs::write(&tmp, "rule test {}").expect("write tmp");
        assert!(should_replace_yara_rules(&tmp).expect("check tmp"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn quarantine_file_moves_file() {
        let dir = std::env::temp_dir();
        let source = dir.join("yara_quarantine_source.txt");
        let quarantine = dir.join("yara_quarantine_dir");
        std::fs::write(&source, "data").expect("write source");
        quarantine_file(source.to_str().expect("path"), &quarantine).expect("quarantine");
        assert!(!source.exists());
        let target = quarantine.join("yara_quarantine_source.txt");
        assert!(target.exists());
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir_all(&quarantine);
    }

    #[test]
    fn quarantine_writes_sidecar_metadata() {
        let root = std::env::temp_dir().join(format!(
            "tamsilcms_quarantine_meta_{}_{}",
            std::process::id(),
            now_unix().unwrap_or(0)
        ));
        let source_dir = root.join("source");
        let quarantine_dir = root.join("quarantine");
        let source = source_dir.join("sample.bin");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        std::fs::write(&source, "data").expect("write source");

        let target = quarantine_file_with_metadata(
            source.to_str().expect("source path"),
            &quarantine_dir,
            "unit_test",
            Some("abc123"),
        )
        .expect("quarantine with metadata");

        let sidecar = quarantine_sidecar_path(&target);
        assert!(target.exists());
        assert!(sidecar.exists());

        let sidecar_json: Value = serde_json::from_str(
            &std::fs::read_to_string(&sidecar).expect("read sidecar"),
        )
        .expect("parse sidecar");
        assert_eq!(
            sidecar_json
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            "unit_test"
        );
        assert_eq!(
            sidecar_json
                .get("source_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            "abc123"
        );
        assert_eq!(
            sidecar_json
                .get("original_path")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            source.to_string_lossy()
        );

        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&sidecar);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_prefers_original_path_and_cleans_sidecar() {
        let root = std::env::temp_dir().join(format!(
            "tamsilcms_restore_meta_{}_{}",
            std::process::id(),
            now_unix().unwrap_or(0)
        ));
        let source_dir = root.join("source");
        let quarantine_dir = root.join("quarantine");
        let source = source_dir.join("sample_restore.bin");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        std::fs::write(&source, "payload").expect("write source");

        let quarantined = quarantine_file_with_metadata(
            source.to_str().expect("source path"),
            &quarantine_dir,
            "unit_test_restore",
            None,
        )
        .expect("quarantine source");
        let sidecar = quarantine_sidecar_path(&quarantined);
        assert!(sidecar.exists());

        let restored = restore_quarantined_file(
            quarantined.to_str().expect("quarantined path"),
            &quarantine_dir,
            true,
        )
        .expect("restore file");

        assert!(restored.exists());
        assert_eq!(restored, source);
        assert!(!quarantined.exists());
        assert!(!sidecar.exists());

        let _ = std::fs::remove_file(&restored);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_to_restored_folder_when_original_mode_disabled() {
        let root = std::env::temp_dir().join(format!(
            "tamsilcms_restore_folder_{}_{}",
            std::process::id(),
            now_unix().unwrap_or(0)
        ));
        let source_dir = root.join("source");
        let quarantine_dir = root.join("quarantine");
        let source = source_dir.join("sample_restore_folder.bin");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        std::fs::write(&source, "payload").expect("write source");

        let quarantined = quarantine_file_with_metadata(
            source.to_str().expect("source path"),
            &quarantine_dir,
            "unit_test_restore_folder",
            None,
        )
        .expect("quarantine source");

        let restored = restore_quarantined_file(
            quarantined.to_str().expect("quarantined path"),
            &quarantine_dir,
            false,
        )
        .expect("restore file into restored folder");

        let expected_prefix = quarantine_dir.join("restored");
        assert!(restored.starts_with(&expected_prefix));
        assert!(restored.exists());
        assert!(!source.exists());

        let _ = std::fs::remove_file(&restored);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_removes_file_and_sidecar() {
        let root = std::env::temp_dir().join(format!(
            "tamsilcms_delete_meta_{}_{}",
            std::process::id(),
            now_unix().unwrap_or(0)
        ));
        let source_dir = root.join("source");
        let quarantine_dir = root.join("quarantine");
        let source = source_dir.join("sample_delete.bin");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        std::fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        std::fs::write(&source, "payload").expect("write source");

        let quarantined = quarantine_file_with_metadata(
            source.to_str().expect("source path"),
            &quarantine_dir,
            "unit_test_delete",
            None,
        )
        .expect("quarantine source");
        let sidecar = quarantine_sidecar_path(&quarantined);
        assert!(quarantined.exists());
        assert!(sidecar.exists());

        delete_quarantined_file(quarantined.to_str().expect("quarantined path"), &quarantine_dir)
            .expect("delete quarantined file");

        assert!(!quarantined.exists());
        assert!(!sidecar.exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_processed_events_advances_monotonically() {
        let events = vec![
            SensorEvent {
                ts_unix: 10,
                source: "journalctl".to_string(),
                kind: "kernel_signal".to_string(),
                severity: "low".to_string(),
                message: "a".to_string(),
            },
            SensorEvent {
                ts_unix: 5,
                source: "journalctl".to_string(),
                kind: "kernel_signal".to_string(),
                severity: "low".to_string(),
                message: "b".to_string(),
            },
        ];

        let processed = build_processed_kernel_events(events, 100, 12);
        assert_eq!(processed[0].1, 13);
        assert_eq!(processed[1].1, 14);
    }
}
