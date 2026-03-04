#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]
#![allow(unused_attributes)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct UiAlert {
    rule: String,
    severity: String,
    message: String,
    pid: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct UiIncident {
    incident_id: String,
    primary_pid: i32,
    risk_score: u32,
    alert_count: usize,
    summary: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct AgentStatus {
    timestamp_unix: u64,
    alert_count: usize,
    incident_count: usize,
    highest_severity: String,
    scan_lifecycle: Option<ScanLifecycle>,
    alerts: Vec<UiAlert>,
    incidents: Vec<UiIncident>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct ScanLifecycle {
    state: String,
    mode: String,
    started_at_unix: u64,
    completed_at_unix: Option<u64>,
    duration_ms: u64,
    message: String,
    progress_percent: u32,
}

#[derive(Debug, Clone, Default)]
struct QuarantineEntry {
    file_name: String,
    full_path: String,
    size_bytes: u64,
    modified_unix: u64,
    original_path: Option<String>,
    reason: Option<String>,
    source_hash: Option<String>,
    quarantined_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct QuarantineSidecar {
    original_path: Option<String>,
    reason: Option<String>,
    source_hash: Option<String>,
    quarantined_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct BackendAlert {
    id: i64,
    title: String,
    description: String,
    severity: String,
    endpoint_id: i32,
    timestamp: String,
    status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewTab {
    Overview,
    Alerts,
    Incidents,
    Quarantine,
    CloudAlerts,
}

struct EndpointUiApp {
    status_path: PathBuf,
    command_path: PathBuf,
    quarantine_dir: PathBuf,
    status: AgentStatus,
    status_message: String,
    last_refresh: Option<Instant>,
    backend_url: Option<String>,
    backend_api_key: Option<String>,
    backend_endpoint_id: Option<i32>,
    backend_alerts: Vec<BackendAlert>,
    backend_status_message: String,
    backend_last_refresh: Option<Instant>,
    backend_severity_filter: String,
    backend_status_filter: String,
    active_tab: ViewTab,
    command_history: Vec<String>,
    quarantine_entries: Vec<QuarantineEntry>,
    restore_to_original_preference: bool,
}

impl EndpointUiApp {
    fn new() -> Self {
        let program_data = env::var("PROGRAMDATA").unwrap_or_else(|_| "C:/ProgramData".to_string());
        let base = PathBuf::from(program_data.clone())
            .join("TamsilCMS")
            .join("state");

        let status_path = env::var("TAMSILCMS_UI_STATUS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base.join("agent_status.json"));
        let command_path = env::var("TAMSILCMS_UI_COMMAND_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base.join("agent_command.json"));
        let quarantine_dir = env::var("TAMSILCMS_UI_QUARANTINE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(program_data).join("TamsilCMS").join("quarantine"));

        let backend_url = env::var("TAMSILCMS_UI_BACKEND_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let backend_api_key = env::var("TAMSILCMS_UI_API_KEY")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let backend_endpoint_id = env::var("TAMSILCMS_UI_ENDPOINT_ID")
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok());

        if let Some(parent) = status_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Some(parent) = command_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::create_dir_all(&quarantine_dir);
        if !status_path.exists() {
            let initial = AgentStatus::default();
            if let Ok(serialized) = serde_json::to_string_pretty(&initial) {
                let _ = fs::write(&status_path, serialized);
            }
        }

        Self {
            status_path,
            command_path,
            quarantine_dir,
            status: AgentStatus::default(),
            status_message: "Waiting for agent status...".to_string(),
            last_refresh: None,
            backend_url,
            backend_api_key,
            backend_endpoint_id,
            backend_alerts: Vec::new(),
            backend_status_message: "Cloud alerts unavailable".to_string(),
            backend_last_refresh: None,
            backend_severity_filter: String::new(),
            backend_status_filter: String::new(),
            active_tab: ViewTab::Overview,
            command_history: Vec::new(),
            quarantine_entries: Vec::new(),
            restore_to_original_preference: true,
        }
    }

    fn refresh_status(&mut self) {
        match fs::read_to_string(&self.status_path) {
            Ok(content) => match serde_json::from_str::<AgentStatus>(&content) {
                Ok(status) => {
                    self.status = status;
                    self.status_message = "Status updated".to_string();
                    self.last_refresh = Some(Instant::now());
                }
                Err(err) => {
                    self.status_message = format!("Invalid status JSON: {}", err);
                }
            },
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.status_message = "Waiting for agent status...".to_string();
                } else {
                    self.status_message = format!("Status unavailable: {}", err);
                }
            }
        }
    }

    fn send_command(&mut self, action: &str) {
        self.send_command_with_target(action, None, None);
    }

    fn send_command_with_target(
        &mut self,
        action: &str,
        target_path: Option<&str>,
        restore_to_original: Option<bool>,
    ) {
        if let Some(parent) = self.command_path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                self.status_message = format!("Failed to create command directory: {}", err);
                return;
            }
        }

        let mut payload = json!({
            "action": action,
            "requested_at_unix": now_unix(),
            "source": "endpoint_ui",
        });

        if let Some(target) = target_path {
            payload["target_path"] = serde_json::Value::String(target.to_string());
        }
        if let Some(value) = restore_to_original {
            payload["restore_to_original"] = serde_json::Value::Bool(value);
        }

        let tmp_path = self.command_path.with_extension("tmp");
        let serialized = match serde_json::to_string_pretty(&payload) {
            Ok(v) => v,
            Err(err) => {
                self.status_message = format!("Failed to encode command: {}", err);
                return;
            }
        };

        if let Err(err) = fs::write(&tmp_path, serialized) {
            self.status_message = format!("Failed to write command temp file: {}", err);
            return;
        }

        if let Err(err) = fs::rename(&tmp_path, &self.command_path) {
            let _ = fs::remove_file(&tmp_path);
            self.status_message = format!("Failed to commit command file: {}", err);
            return;
        }

        self.status_message = format!("Command queued: {}", action);
        let history_item = if let Some(target) = target_path {
            let mode = restore_to_original
                .map(|value| {
                    if value {
                        "original"
                    } else {
                        "restored"
                    }
                })
                .unwrap_or("n/a");
            format!("{} | {} | {} | mode={} ", now_unix(), action, target, mode)
        } else {
            format!("{} | {}", now_unix(), action)
        };
        self.command_history.push(history_item);
        if self.command_history.len() > 30 {
            let drop_count = self.command_history.len() - 30;
            self.command_history.drain(0..drop_count);
        }
    }

    fn refresh_backend_alerts(&mut self) {
        let backend_url = match &self.backend_url {
            Some(value) => value,
            None => {
                self.backend_status_message =
                    "Set TAMSILCMS_UI_BACKEND_URL to enable cloud alert view".to_string();
                return;
            }
        };

        let client = match Client::builder().timeout(Duration::from_secs(8)).build() {
            Ok(value) => value,
            Err(err) => {
                self.backend_status_message = format!("Cloud client init failed: {}", err);
                return;
            }
        };

        let mut request = client
            .get(format!("{}/edr/alerts", backend_url.trim_end_matches('/')))
            .query(&[("limit", "100")]);

        if let Some(endpoint_id) = self.backend_endpoint_id {
            request = request.query(&[("endpoint_id", endpoint_id)]);
        }

        if !self.backend_severity_filter.trim().is_empty() {
            request = request.query(&[("severity", self.backend_severity_filter.trim())]);
        }

        if !self.backend_status_filter.trim().is_empty() {
            request = request.query(&[("status", self.backend_status_filter.trim())]);
        }

        if let Some(api_key) = &self.backend_api_key {
            request = request.header("X-API-Key", api_key);
        }

        match request.send() {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok_resp) => match ok_resp.json::<Vec<BackendAlert>>() {
                    Ok(alerts) => {
                        self.backend_alerts = alerts;
                        self.backend_status_message = format!(
                            "Cloud alerts updated ({} records)",
                            self.backend_alerts.len()
                        );
                        self.backend_last_refresh = Some(Instant::now());
                    }
                    Err(err) => {
                        self.backend_status_message = format!("Cloud parse failed: {}", err);
                    }
                },
                Err(err) => {
                    self.backend_status_message = format!("Cloud API error: {}", err);
                }
            },
            Err(err) => {
                self.backend_status_message = format!("Cloud request failed: {}", err);
            }
        }
    }

    fn refresh_quarantine_entries(&mut self) {
        let entries = match fs::read_dir(&self.quarantine_dir) {
            Ok(items) => items,
            Err(_) => {
                self.quarantine_entries.clear();
                return;
            }
        };

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path
                .file_name()
                .map(|name| name.to_string_lossy().ends_with(".quarantine.json"))
                .unwrap_or(false)
            {
                continue;
            }

            if let Ok(meta) = entry.metadata() {
                let modified_unix = meta
                    .modified()
                    .ok()
                    .and_then(|ts| ts.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let sidecar_path = path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(format!("{}.quarantine.json", path.file_name().unwrap_or_default().to_string_lossy()));
                let sidecar = fs::read_to_string(&sidecar_path)
                    .ok()
                    .and_then(|content| serde_json::from_str::<QuarantineSidecar>(&content).ok())
                    .unwrap_or_default();

                out.push(QuarantineEntry {
                    file_name: path
                        .file_name()
                        .map(|v| v.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    full_path: path.to_string_lossy().to_string(),
                    size_bytes: meta.len(),
                    modified_unix,
                    original_path: sidecar
                        .original_path
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    reason: sidecar
                        .reason
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    source_hash: sidecar
                        .source_hash
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    quarantined_at_unix: sidecar.quarantined_at_unix,
                });
            }
        }

        out.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix));
        self.quarantine_entries = out;
    }
}

impl eframe::App for EndpointUiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_secs(2));

        let should_auto_refresh = match self.last_refresh {
            Some(last) => last.elapsed() >= Duration::from_secs(2),
            None => true,
        };
        if should_auto_refresh {
            self.refresh_status();
            self.refresh_quarantine_entries();
        }

        let should_refresh_backend = match self.backend_last_refresh {
            Some(last) => last.elapsed() >= Duration::from_secs(8),
            None => true,
        };
        if should_refresh_backend {
            self.refresh_backend_alerts();
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TamsilCMS Endpoint Protection");
                ui.separator();
                ui.label(format!("Status file: {}", self.status_path.display()));
                ui.separator();
                ui.label(format!("Quarantine: {}", self.quarantine_dir.display()));
            });
            ui.label(self.status_message.clone());
            ui.label(self.backend_status_message.clone());
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.label("Protection");
                    ui.heading(self.status.highest_severity.to_uppercase());
                });
                ui.group(|ui| {
                    ui.label("Alerts");
                    ui.heading(self.status.alert_count.to_string());
                });
                ui.group(|ui| {
                    ui.label("Incidents");
                    ui.heading(self.status.incident_count.to_string());
                });
                ui.group(|ui| {
                    ui.label("Last Scan");
                    ui.heading(self.status.timestamp_unix.to_string());
                });
                ui.group(|ui| {
                    ui.label("Quarantine Files");
                    ui.heading(self.quarantine_entries.len().to_string());
                });
            });

            if let Some(scan) = &self.status.scan_lifecycle {
                ui.horizontal(|ui| {
                    ui.group(|ui| {
                        ui.label("Scan State");
                        ui.heading(scan.state.to_uppercase());
                    });
                    ui.group(|ui| {
                        ui.label("Scan Mode");
                        ui.heading(scan.mode.to_uppercase());
                    });
                    ui.group(|ui| {
                        ui.label("Progress");
                        ui.heading(format!("{}%", scan.progress_percent));
                    });
                    ui.group(|ui| {
                        ui.label("Duration");
                        ui.heading(format!("{} ms", scan.duration_ms));
                    });
                });
                ui.label(format!(
                    "{} (started {} completed {:?})",
                    scan.message, scan.started_at_unix, scan.completed_at_unix
                ));
            }

            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Quick Scan").clicked() {
                    self.send_command("quick_scan");
                }
                if ui.button("Full Scan").clicked() {
                    self.send_command("full_scan");
                }
                if ui.button("Memory Scan").clicked() {
                    self.send_command("memory_scan");
                }
                if ui.button("Refresh").clicked() {
                    self.refresh_status();
                    self.refresh_backend_alerts();
                    self.refresh_quarantine_entries();
                }
            });

            ui.horizontal(|ui| {
                ui.label("Cloud severity");
                ui.text_edit_singleline(&mut self.backend_severity_filter);
                ui.label("Cloud status");
                ui.text_edit_singleline(&mut self.backend_status_filter);
                if ui.button("Apply Cloud Filters").clicked() {
                    self.refresh_backend_alerts();
                }
            });

            ui.separator();

            ui.horizontal(|ui| {
                let is_overview = self.active_tab == ViewTab::Overview;
                if ui.selectable_label(is_overview, "Overview").clicked() {
                    self.active_tab = ViewTab::Overview;
                }
                let is_alerts = self.active_tab == ViewTab::Alerts;
                if ui.selectable_label(is_alerts, "Local Alerts").clicked() {
                    self.active_tab = ViewTab::Alerts;
                }
                let is_incidents = self.active_tab == ViewTab::Incidents;
                if ui.selectable_label(is_incidents, "Incidents").clicked() {
                    self.active_tab = ViewTab::Incidents;
                }
                let is_quarantine = self.active_tab == ViewTab::Quarantine;
                if ui.selectable_label(is_quarantine, "Quarantine").clicked() {
                    self.active_tab = ViewTab::Quarantine;
                }
                let is_cloud = self.active_tab == ViewTab::CloudAlerts;
                if ui.selectable_label(is_cloud, "Cloud Alerts").clicked() {
                    self.active_tab = ViewTab::CloudAlerts;
                }
            });

            ui.separator();

            match self.active_tab {
                ViewTab::Overview => {
                    ui.heading("Action Center");
                    egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                        for item in self.command_history.iter().rev() {
                            ui.label(item);
                        }
                    });

                    ui.separator();
                    ui.heading("Latest Local Findings");
                    egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        for alert in self.status.alerts.iter().take(25) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!(
                                    "[{}] {}",
                                    alert.severity.to_uppercase(),
                                    alert.rule
                                ));
                                ui.label(alert.message.clone());
                            });
                            ui.separator();
                        }
                    });
                }
                ViewTab::Alerts => {
                    ui.heading("Local Alerts");
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for alert in self.status.alerts.iter().take(200) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!(
                                    "[{}] {}",
                                    alert.severity.to_uppercase(),
                                    alert.rule
                                ));
                                if let Some(pid) = alert.pid {
                                    ui.label(format!("PID {}", pid));
                                }
                                ui.label(alert.message.clone());
                            });
                            ui.separator();
                        }
                    });
                }
                ViewTab::Incidents => {
                    ui.heading("Local Incidents");
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for incident in self.status.incidents.iter().take(100) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(incident.incident_id.clone());
                                ui.label(format!("risk {}", incident.risk_score));
                                ui.label(format!("pid {}", incident.primary_pid));
                                ui.label(format!("alerts {}", incident.alert_count));
                                ui.label(incident.summary.clone());
                            });
                            ui.separator();
                        }
                    });
                }
                ViewTab::CloudAlerts => {
                    ui.heading("Backend Alerts (/edr/alerts)");
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for alert in self.backend_alerts.iter().take(200) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!(
                                    "#{} [{}] {}",
                                    alert.id,
                                    alert.severity.to_uppercase(),
                                    alert.title
                                ));
                                ui.label(format!("endpoint {}", alert.endpoint_id));
                                ui.label(format!("status {}", alert.status));
                                ui.label(alert.timestamp.clone());
                            });
                            ui.label(alert.description.clone());
                            ui.separator();
                        }
                    });
                }
                ViewTab::Quarantine => {
                    ui.heading("Quarantine");
                    ui.label(format!("Directory: {}", self.quarantine_dir.display()));
                    ui.label(format!(
                        "Restore destination: {}",
                        self.quarantine_dir.join("restored").display()
                    ));
                    ui.checkbox(
                        &mut self.restore_to_original_preference,
                        "Restore to original location when metadata is available",
                    );

                    let mut queued_action: Option<(String, String, Option<bool>)> = None;
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for entry in self.quarantine_entries.iter().take(500) {
                            egui::CollapsingHeader::new(format!(
                                "{} ({} bytes)",
                                entry.file_name, entry.size_bytes
                            ))
                            .id_salt(&entry.full_path)
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(format!("modified {}", entry.modified_unix));
                                    if let Some(reason) = &entry.reason {
                                        ui.label(format!("reason {}", reason));
                                    }
                                });
                                ui.label(format!("path {}", entry.full_path));
                                if let Some(original_path) = &entry.original_path {
                                    ui.label(format!("original {}", original_path));
                                }
                                if let Some(source_hash) = &entry.source_hash {
                                    ui.label(format!("hash {}", source_hash));
                                }
                                if let Some(quarantined_at) = entry.quarantined_at_unix {
                                    ui.label(format!("quarantined_at {}", quarantined_at));
                                }

                                ui.horizontal(|ui| {
                                    if ui.button("Restore").clicked() {
                                        queued_action = Some((
                                            "restore_quarantine".to_string(),
                                            entry.full_path.clone(),
                                            Some(self.restore_to_original_preference),
                                        ));
                                    }
                                    if ui.button("Delete").clicked() {
                                        queued_action = Some((
                                            "delete_quarantine".to_string(),
                                            entry.full_path.clone(),
                                            None,
                                        ));
                                    }
                                });
                            });
                            ui.separator();
                        }
                    });
                    if let Some((action, target, restore_mode)) = queued_action {
                        self.send_command_with_target(&action, Some(&target), restore_mode);
                        self.refresh_quarantine_entries();
                    }
                }
            }
        });
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
const BTN_QUICK_SCAN: usize = 1001;
#[cfg(target_os = "windows")]
const BTN_FULL_SCAN: usize = 1002;
#[cfg(target_os = "windows")]
const BTN_STOP_SCAN: usize = 1003;
#[cfg(target_os = "windows")]
const BTN_REFRESH: usize = 1004;
#[cfg(target_os = "windows")]
const BTN_CLOUD: usize = 1005;
#[cfg(target_os = "windows")]
const BTN_CLOSE: usize = 1006;
#[cfg(target_os = "windows")]
const TIMER_REFRESH_ID: usize = 2001;

#[cfg(target_os = "windows")]
struct NativeFallbackState {
    app: EndpointUiApp,
    status_label: windows::Win32::Foundation::HWND,
    metrics_label: windows::Win32::Foundation::HWND,
    path_label: windows::Win32::Foundation::HWND,
}

#[cfg(target_os = "windows")]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn update_native_labels(state: &mut NativeFallbackState) {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::SetWindowTextW;

    state.app.refresh_status();
    state.app.refresh_quarantine_entries();
    state.app.refresh_backend_alerts();

    let status_text = wide("Endpoint Secured · Desktop Compatibility Mode");
    let metrics_text = wide(&format!(
        "Status: {}\r\nAlerts: {}   Incidents: {}   Quarantine: {}   Cloud Alerts: {}\r\nLast Refresh: {}",
        state.app.status_message,
        state.app.status.alert_count,
        state.app.status.incident_count,
        state.app.quarantine_entries.len(),
        state.app.backend_alerts.len(),
        now_unix(),
    ));
    let path_text = wide(&format!(
        "Status File: {}\r\nCommand File: {}\r\nQuarantine Dir: {}",
        state.app.status_path.display(),
        state.app.command_path.display(),
        state.app.quarantine_dir.display(),
    ));

    unsafe {
        let _ = SetWindowTextW(state.status_label, PCWSTR(status_text.as_ptr()));
        let _ = SetWindowTextW(state.metrics_label, PCWSTR(metrics_text.as_ptr()));
        let _ = SetWindowTextW(state.path_label, PCWSTR(path_text.as_ptr()));
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn native_fallback_wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, DestroyWindow, GetWindowLongPtrW, KillTimer, PostQuitMessage,
        SetWindowLongPtrW, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_NCDESTROY, WM_TIMER,
    };

    let state_ptr = GetWindowLongPtrW(hwnd, windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA)
        as *mut NativeFallbackState;

    match msg {
        WM_COMMAND => {
            let command_id = wparam.0 & 0xffff;
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                match command_id {
                    BTN_QUICK_SCAN => state.app.send_command("quick_scan"),
                    BTN_FULL_SCAN => state.app.send_command("full_scan"),
                    BTN_STOP_SCAN => state.app.send_command("stop_scan"),
                    BTN_REFRESH => {
                        state.app.refresh_status();
                        state.app.refresh_quarantine_entries();
                    }
                    BTN_CLOUD => state.app.refresh_backend_alerts(),
                    BTN_CLOSE => {
                        let _ = DestroyWindow(hwnd);
                        return windows::Win32::Foundation::LRESULT(0);
                    }
                    _ => {}
                }
                update_native_labels(state);
            }
            windows::Win32::Foundation::LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_REFRESH_ID && !state_ptr.is_null() {
                let state = &mut *state_ptr;
                update_native_labels(state);
            }
            windows::Win32::Foundation::LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            windows::Win32::Foundation::LRESULT(0)
        }
        WM_DESTROY => {
            let _ = KillTimer(hwnd, TIMER_REFRESH_ID);
            PostQuitMessage(0);
            windows::Win32::Foundation::LRESULT(0)
        }
        WM_NCDESTROY => {
            if !state_ptr.is_null() {
                let _ = Box::from_raw(state_ptr);
                let _ = SetWindowLongPtrW(
                    hwnd,
                    windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
                    0,
                );
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(target_os = "windows")]
fn run_native_fallback_window() -> Result<(), String> {
    use std::ffi::c_void;
    use windows::core::w;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetMessageW, LoadCursorW, RegisterClassW,
        HMENU,
        SetTimer, SetWindowLongPtrW, ShowWindow, TranslateMessage,
        IDC_ARROW, MSG, SW_SHOW, WINDOW_EX_STYLE, WNDCLASSW,
        WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    let class_name = w!("TamsilCmsFallbackUiClass");
    let wnd_class = WNDCLASSW {
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
        lpszClassName: class_name,
        lpfnWndProc: Some(native_fallback_wndproc),
        ..Default::default()
    };

    unsafe {
        if RegisterClassW(&wnd_class) == 0 {
            return Err("Failed to register fallback window class".to_string());
        }

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("TamsilCMS Endpoint UI"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            200,
            120,
            980,
            640,
            None,
            None,
            None,
            None::<*const c_void>,
        );

        if hwnd.0 == 0 {
            return Err("Failed to create fallback window".to_string());
        }

        let title = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            w!("TamsilCMS Endpoint Security Console"),
            WS_CHILD | WS_VISIBLE,
            24,
            20,
            720,
            30,
            hwnd,
            HMENU(0),
            None,
            None::<*const c_void>,
        );

        let metrics = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            w!("Initializing telemetry..."),
            WS_CHILD | WS_VISIBLE,
            24,
            70,
            900,
            90,
            hwnd,
            HMENU(0),
            None,
            None::<*const c_void>,
        );

        let paths = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            w!("Initializing paths..."),
            WS_CHILD | WS_VISIBLE,
            24,
            180,
            900,
            120,
            hwnd,
            HMENU(0),
            None,
            None::<*const c_void>,
        );

        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Quick Scan"),
            WS_CHILD | WS_VISIBLE,
            24,
            340,
            120,
            36,
            hwnd,
            HMENU(BTN_QUICK_SCAN as isize),
            None,
            None::<*const c_void>,
        );
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Full Scan"),
            WS_CHILD | WS_VISIBLE,
            154,
            340,
            120,
            36,
            hwnd,
            HMENU(BTN_FULL_SCAN as isize),
            None,
            None::<*const c_void>,
        );
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Stop"),
            WS_CHILD | WS_VISIBLE,
            284,
            340,
            90,
            36,
            hwnd,
            HMENU(BTN_STOP_SCAN as isize),
            None,
            None::<*const c_void>,
        );
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Refresh"),
            WS_CHILD | WS_VISIBLE,
            384,
            340,
            100,
            36,
            hwnd,
            HMENU(BTN_REFRESH as isize),
            None,
            None::<*const c_void>,
        );
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Cloud Alerts"),
            WS_CHILD | WS_VISIBLE,
            494,
            340,
            120,
            36,
            hwnd,
            HMENU(BTN_CLOUD as isize),
            None,
            None::<*const c_void>,
        );
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Close"),
            WS_CHILD | WS_VISIBLE,
            624,
            340,
            100,
            36,
            hwnd,
            HMENU(BTN_CLOSE as isize),
            None,
            None::<*const c_void>,
        );

        let mut state = Box::new(NativeFallbackState {
            app: EndpointUiApp::new(),
            status_label: title,
            metrics_label: metrics,
            path_label: paths,
        });
        update_native_labels(&mut state);

        let _ = SetWindowLongPtrW(
            hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            Box::into_raw(state) as isize,
        );

        let _ = SetTimer(hwnd, TIMER_REFRESH_ID, 2000, None);
        ShowWindow(hwnd, SW_SHOW);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND(0), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            let _ = DispatchMessageW(&msg);
        }
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn run_native_fallback_window() -> Result<(), String> {
    Err("Native fallback window is only implemented on Windows".to_string())
}

#[allow(dead_code)]
fn main() -> Result<(), eframe::Error> {
    endpoint_ui_entry()
}

pub fn endpoint_ui_entry() -> Result<(), eframe::Error> {
    let run_with_renderer = |renderer: eframe::Renderer| {
        let options = eframe::NativeOptions {
            renderer,
            ..Default::default()
        };
        eframe::run_native(
            "TamsilCMS Endpoint UI",
            options,
            Box::new(|_cc| Ok(Box::new(EndpointUiApp::new()))),
        )
    };

    match run_with_renderer(eframe::Renderer::Wgpu) {
        Ok(()) => Ok(()),
        Err(wgpu_err) => {
            eprintln!("WGPU renderer failed: {wgpu_err}. Retrying with software fallback adapter...");
            std::env::set_var("WGPU_FORCE_FALLBACK_ADAPTER", "1");
            match run_with_renderer(eframe::Renderer::Wgpu) {
                Ok(()) => Ok(()),
                Err(soft_wgpu_err) => {
                    eprintln!(
                        "Software WGPU fallback failed: {soft_wgpu_err}. Falling back to OpenGL renderer..."
                    );
                    match run_with_renderer(eframe::Renderer::Glow) {
                        Ok(()) => Ok(()),
                        Err(glow_err) => {
                            eprintln!(
                                "OpenGL renderer failed: {glow_err}. Starting native fallback window..."
                            );
                            if let Err(err) = run_native_fallback_window() {
                                eprintln!("Native fallback window failed: {err}");
                            }
                            Ok(())
                        }
                    }
                }
            }
        }
    }
}
