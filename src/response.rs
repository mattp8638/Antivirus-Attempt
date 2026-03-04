//! Response Actions Module
//! Automated response execution for EDR agent

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use std::process::Command;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use log::info;

/// Types of response actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    TerminateProcess,
    IsolateEndpoint,
    QuarantineFile,
    BlockIp,
    BlockDomain,
    KillNetwork,
    CollectEvidence,
    DeleteFile,
    RestoreFile,
    UnisolateEndpoint,
}

/// Status of a response action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    RequiresApproval,
    Approved,
    Rejected,
    RolledBack,
}

/// Response action definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: String,
    pub action_type: ActionType,
    pub endpoint_id: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub alert_id: Option<String>,
    pub rule_id: Option<String>,
    pub initiated_by: String,
    pub requires_approval: bool,
    pub status: ActionStatus,
    pub created_at: SystemTime,
    pub executed_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
}

/// Result of executing a response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub action_id: String,
    pub action_type: ActionType,
    pub message: String,
    pub details: HashMap<String, serde_json::Value>,
    pub rollback_info: Option<HashMap<String, serde_json::Value>>,
    pub error: Option<String>,
}

/// Configuration for response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub quarantine_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub audit_log: PathBuf,
    pub enable_network_isolation: bool,
    pub enable_process_termination: bool,
    pub enable_file_quarantine: bool,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: PathBuf::from("/var/tamsilcms/quarantine"),
            evidence_dir: PathBuf::from("/var/tamsilcms/evidence"),
            audit_log: PathBuf::from("/var/log/tamsilcms/response_audit.log"),
            enable_network_isolation: true,
            enable_process_termination: true,
            enable_file_quarantine: true,
        }
    }
}

/// Action executor
pub struct ActionExecutor {
    config: ResponseConfig,
}

impl ActionExecutor {
    /// Create new action executor
    pub fn new(config: ResponseConfig) -> Result<Self> {
        // Create necessary directories
        fs::create_dir_all(&config.quarantine_dir)
            .context("Failed to create quarantine directory")?;
        fs::create_dir_all(&config.evidence_dir)
            .context("Failed to create evidence directory")?;
        
        if let Some(parent) = config.audit_log.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create audit log directory")?;
        }
        
        info!("Response action executor initialized");
        Ok(Self { config })
    }
    
    /// Execute a response action
    pub fn execute(&self, action: &mut ResponseAction) -> Result<ActionResult> {
        info!("Executing action {}: {:?}", action.id, action.action_type);
        
        action.status = ActionStatus::InProgress;
        action.executed_at = Some(SystemTime::now());
        
        self.audit_log(action, "started")?;
        
        let result = match action.action_type {
            ActionType::TerminateProcess => self.terminate_process(action),
            ActionType::IsolateEndpoint => self.isolate_endpoint(action),
            ActionType::QuarantineFile => self.quarantine_file(action),
            ActionType::BlockIp => self.block_ip(action),
            ActionType::BlockDomain => self.block_domain(action),
            ActionType::KillNetwork => self.kill_network(action),
            ActionType::CollectEvidence => self.collect_evidence(action),
            ActionType::DeleteFile => self.delete_file(action),
            ActionType::RestoreFile => self.restore_file(action),
            ActionType::UnisolateEndpoint => self.unisolate_endpoint(action),
        };
        
        match &result {
            Ok(res) if res.success => {
                action.status = ActionStatus::Completed;
                self.audit_log(action, "completed")?;
            }
            Ok(_) | Err(_) => {
                action.status = ActionStatus::Failed;
                self.audit_log(action, "failed")?;
            }
        }
        
        action.completed_at = Some(SystemTime::now());
        
        result
    }
    
    /// Terminate a process by PID
    fn terminate_process(&self, action: &ResponseAction) -> Result<ActionResult> {
        if !self.config.enable_process_termination {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: "Process termination is disabled".to_string(),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Feature disabled".to_string()),
            });
        }
        
        let pid = action.parameters
            .get("pid")
            .and_then(|v| v.as_u64())
            .context("Missing or invalid 'pid' parameter")?;
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output()
                .context("Failed to execute taskkill")?;
            
            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: format!("Failed to terminate process {}", pid),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .output()
                .context("Failed to execute kill")?;
            
            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: format!("Failed to terminate process {}", pid),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }
        
        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("Process {} terminated successfully", pid),
            details: HashMap::from([("pid".to_string(), serde_json::json!(pid))]),
            rollback_info: None,
            error: None,
        })
    }
    
    /// Isolate endpoint by disabling network
    fn isolate_endpoint(&self, action: &ResponseAction) -> Result<ActionResult> {
        if !self.config.enable_network_isolation {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: "Network isolation is disabled".to_string(),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Feature disabled".to_string()),
            });
        }
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("powershell")
                .args([
                    "-Command",
                    "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false"
                ])
                .output()
                .context("Failed to disable network adapters")?;
            
            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: "Failed to isolate endpoint".to_string(),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Bring down all interfaces except loopback
            let interfaces = vec!["eth0", "ens33", "enp0s3"]; // Common interface names
            for iface in interfaces {
                let _ = Command::new("ip")
                    .args(["link", "set", iface, "down"])
                    .output();
            }
        }
        
        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: "Endpoint isolated successfully".to_string(),
            details: HashMap::new(),
            rollback_info: Some(HashMap::from([
                ("action".to_string(), serde_json::json!("unisolate")),
            ])),
            error: None,
        })
    }
    
    /// Quarantine a file
    fn quarantine_file(&self, action: &ResponseAction) -> Result<ActionResult> {
        if !self.config.enable_file_quarantine {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: "File quarantine is disabled".to_string(),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Feature disabled".to_string()),
            });
        }
        
        let file_path = action.parameters
            .get("file_path")
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'file_path' parameter")?;
        
        let source = PathBuf::from(file_path);
        if !source.exists() {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: format!("File not found: {}", file_path),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("File not found".to_string()),
            });
        }
        
        // Generate quarantine filename
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = source.file_name()
            .context("Invalid filename")?;
        let quarantine_path = self.config.quarantine_dir
            .join(format!("{}_{}", timestamp, filename.to_string_lossy()));
        
        // Move file to quarantine
        fs::rename(&source, &quarantine_path)
            .context("Failed to move file to quarantine")?;
        
        // Create manifest
        let manifest = serde_json::json!({
            "original_path": file_path,
            "quarantine_path": quarantine_path.to_string_lossy(),
            "quarantined_at": chrono::Utc::now().to_rfc3339(),
            "action_id": action.id,
        });
        
        let manifest_path = quarantine_path.with_extension("json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest")?;
        
        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("File quarantined: {}", file_path),
            details: HashMap::from([
                ("original_path".to_string(), serde_json::json!(file_path)),
                ("quarantine_path".to_string(), serde_json::json!(quarantine_path.to_string_lossy())),
            ]),
            rollback_info: Some(HashMap::from([
                ("original_path".to_string(), serde_json::json!(file_path)),
                ("quarantine_path".to_string(), serde_json::json!(quarantine_path.to_string_lossy())),
            ])),
            error: None,
        })
    }
    
    /// Block an IP address
    fn block_ip(&self, action: &ResponseAction) -> Result<ActionResult> {
        let ip = action.parameters
            .get("ip_address")
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'ip_address' parameter")?;
        
        #[cfg(target_os = "windows")]
        {
            let rule_name = format!("TamsilCMS_Block_{}", ip);
            let output = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={}", ip),
                ])
                .output()
                .context("Failed to execute netsh")?;
            
            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: format!("Failed to block IP {}", ip),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("iptables")
                .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
                .output()
                .context("Failed to execute iptables")?;
            
            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: format!("Failed to block IP {}", ip),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }
        
        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("IP address blocked: {}", ip),
            details: HashMap::from([("ip_address".to_string(), serde_json::json!(ip))]),
            rollback_info: Some(HashMap::from([("ip_address".to_string(), serde_json::json!(ip))])),
            error: None,
        })
    }

    /// Block a domain by adding a hosts entry
    fn block_domain(&self, action: &ResponseAction) -> Result<ActionResult> {
        let domain = action.parameters
            .get("domain")
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'domain' parameter")?;

        let hosts_path = if cfg!(target_os = "windows") {
            PathBuf::from("C:/Windows/System32/drivers/etc/hosts")
        } else {
            PathBuf::from("/etc/hosts")
        };

        let entry = format!("0.0.0.0 {domain}");
        let existing = fs::read_to_string(&hosts_path).unwrap_or_default();
        if !existing.lines().any(|line| line.trim_end() == entry) {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&hosts_path)
                .context("Failed to open hosts file")?;
            writeln!(file, "{entry}").context("Failed to update hosts file")?;
        }

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("Domain blocked via hosts file: {}", domain),
            details: HashMap::from([
                ("domain".to_string(), serde_json::json!(domain)),
                ("hosts_path".to_string(), serde_json::json!(hosts_path)),
            ]),
            rollback_info: Some(HashMap::from([
                ("domain".to_string(), serde_json::json!(domain)),
                ("hosts_path".to_string(), serde_json::json!(hosts_path)),
            ])),
            error: None,
        })
    }

    /// Disable all network access
    fn kill_network(&self, action: &ResponseAction) -> Result<ActionResult> {
        if !self.config.enable_network_isolation {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: "Network kill switch is disabled".to_string(),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Feature disabled".to_string()),
            });
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("powershell")
                .args([
                    "-Command",
                    "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false",
                ])
                .output()
                .context("Failed to disable network adapters")?;

            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: "Failed to kill network access".to_string(),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }

        #[cfg(target_os = "linux")]
        {
            let interfaces = vec!["eth0", "ens33", "enp0s3"];
            for iface in interfaces {
                let _ = Command::new("ip")
                    .args(["link", "set", iface, "down"])
                    .output();
            }
        }

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: "Network access disabled".to_string(),
            details: HashMap::new(),
            rollback_info: Some(HashMap::from([(
                "action".to_string(),
                serde_json::json!("unisolate"),
            )])),
            error: None,
        })
    }

    /// Collect evidence to a local bundle
    fn collect_evidence(&self, action: &ResponseAction) -> Result<ActionResult> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let evidence_dir = self
            .config
            .evidence_dir
            .join(format!("evidence_{}_{}", action.id, timestamp));
        fs::create_dir_all(&evidence_dir).context("Failed to create evidence directory")?;

        if let Some(file_path) = action.parameters.get("file_path").and_then(|v| v.as_str()) {
            let source = PathBuf::from(file_path);
            if source.exists() {
                let filename = source
                    .file_name()
                    .context("Invalid filename")?
                    .to_string_lossy()
                    .to_string();
                let dest = evidence_dir.join(filename);
                let _ = fs::copy(&source, &dest);
            }
        }

        let manifest = serde_json::json!({
            "action_id": action.id,
            "action_type": action.action_type,
            "endpoint_id": action.endpoint_id,
            "collected_at": chrono::Utc::now().to_rfc3339(),
            "parameters": action.parameters,
        });
        let manifest_path = evidence_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write evidence manifest")?;

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: "Evidence collected".to_string(),
            details: HashMap::from([(
                "evidence_dir".to_string(),
                serde_json::json!(evidence_dir),
            )]),
            rollback_info: None,
            error: None,
        })
    }

    /// Delete a file with rollback support
    fn delete_file(&self, action: &ResponseAction) -> Result<ActionResult> {
        let file_path = action.parameters
            .get("file_path")
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'file_path' parameter")?;

        let source = PathBuf::from(file_path);
        if !source.exists() {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: format!("File not found: {}", file_path),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("File not found".to_string()),
            });
        }

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = source.file_name().context("Invalid filename")?;
        let backup_path = self
            .config
            .quarantine_dir
            .join(format!("deleted_{}_{}", timestamp, filename.to_string_lossy()));

        fs::rename(&source, &backup_path).context("Failed to move file for deletion")?;

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("File deleted: {}", file_path),
            details: HashMap::from([
                ("original_path".to_string(), serde_json::json!(file_path)),
                ("backup_path".to_string(), serde_json::json!(backup_path)),
            ]),
            rollback_info: Some(HashMap::from([
                ("original_path".to_string(), serde_json::json!(file_path)),
                ("backup_path".to_string(), serde_json::json!(backup_path)),
            ])),
            error: None,
        })
    }

    /// Restore a previously deleted file
    fn restore_file(&self, action: &ResponseAction) -> Result<ActionResult> {
        let original_path = action.parameters
            .get("original_path")
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'original_path' parameter")?;
        let backup_path = action.parameters
            .get("backup_path")
            .or_else(|| action.parameters.get("quarantine_path"))
            .and_then(|v| v.as_str())
            .context("Missing or invalid 'backup_path' parameter")?;

        let source = PathBuf::from(backup_path);
        if !source.exists() {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: format!("Backup not found: {}", backup_path),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Backup not found".to_string()),
            });
        }

        let dest = PathBuf::from(original_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::rename(&source, &dest).context("Failed to restore file")?;

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: format!("File restored: {}", original_path),
            details: HashMap::from([("original_path".to_string(), serde_json::json!(original_path))]),
            rollback_info: None,
            error: None,
        })
    }

    /// Undo endpoint isolation
    fn unisolate_endpoint(&self, action: &ResponseAction) -> Result<ActionResult> {
        if !self.config.enable_network_isolation {
            return Ok(ActionResult {
                success: false,
                action_id: action.id.clone(),
                action_type: action.action_type.clone(),
                message: "Network isolation is disabled".to_string(),
                details: HashMap::new(),
                rollback_info: None,
                error: Some("Feature disabled".to_string()),
            });
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("powershell")
                .args([
                    "-Command",
                    "Get-NetAdapter | Where-Object {$_.Status -ne 'Up'} | Enable-NetAdapter -Confirm:$false",
                ])
                .output()
                .context("Failed to enable network adapters")?;

            if !output.status.success() {
                return Ok(ActionResult {
                    success: false,
                    action_id: action.id.clone(),
                    action_type: action.action_type.clone(),
                    message: "Failed to unisolate endpoint".to_string(),
                    details: HashMap::new(),
                    rollback_info: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                });
            }
        }

        #[cfg(target_os = "linux")]
        {
            let interfaces = vec!["eth0", "ens33", "enp0s3"];
            for iface in interfaces {
                let _ = Command::new("ip")
                    .args(["link", "set", iface, "up"])
                    .output();
            }
        }

        Ok(ActionResult {
            success: true,
            action_id: action.id.clone(),
            action_type: action.action_type.clone(),
            message: "Endpoint unisolated".to_string(),
            details: HashMap::new(),
            rollback_info: None,
            error: None,
        })
    }

    fn audit_log(&self, action: &ResponseAction, status: &str) -> Result<()> {
        let entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "action_id": action.id,
            "action_type": action.action_type,
            "status": status,
            "endpoint_id": action.endpoint_id,
            "initiated_by": action.initiated_by,
            "requires_approval": action.requires_approval,
        });

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.audit_log)
            .context("Failed to open audit log")?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)
            .context("Failed to write audit log")?;
        Ok(())
    }
}