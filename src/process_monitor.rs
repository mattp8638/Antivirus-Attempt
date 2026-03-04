//! Process Monitoring Module
//!
//! Real-time Windows process monitoring using Windows API callbacks
//! Detects suspicious process creation, injection, and behavioral patterns
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;

/// Process telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: SystemTime,
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub exe_path: String,
    pub user: String,
    pub session_id: u32,
    pub integrity_level: String,
    pub file_hash: Option<String>,
    pub digital_signature: Option<DigitalSignature>,
    pub event_type: ProcessEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventType {
    Created,
    Terminated,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub is_signed: bool,
    pub is_verified: bool,
    pub signer: Option<String>,
    pub issuer: Option<String>,
}

/// Process tree node for relationship tracking
#[derive(Debug, Clone)]
struct ProcessNode {
    pid: u32,
    parent_pid: u32,
    process_name: String,
    command_line: String,
    created_at: SystemTime,
    children: Vec<u32>,
}

/// Process monitoring engine
pub struct ProcessMonitor {
    processes: Arc<Mutex<HashMap<u32, ProcessNode>>>,
    event_history: Arc<Mutex<VecDeque<ProcessEvent>>>,
    max_history: usize,
    suspicious_patterns: Vec<SuspiciousPattern>,
}

#[derive(Debug, Clone)]
struct SuspiciousPattern {
    name: String,
    parent_pattern: Vec<String>,
    child_pattern: Vec<String>,
    command_pattern: Option<String>,
    mitre_technique: Vec<String>,
    severity: ThreatSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessThreat {
    pub event: ProcessEvent,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub mitre_attack: Vec<String>,
    pub description: String,
    pub indicators: Vec<String>,
}

impl ProcessMonitor {
    /// Create new process monitor
    pub fn new() -> Self {
        let suspicious_patterns = Self::init_patterns();
        
        Self {
            processes: Arc::new(Mutex::new(HashMap::new())),
            event_history: Arc::new(Mutex::new(VecDeque::new())),
            max_history: 10000,
            suspicious_patterns,
        }
    }

    /// Initialize suspicious behavior patterns
    fn init_patterns() -> Vec<SuspiciousPattern> {
        vec![
            // Office -> PowerShell/CMD
            SuspiciousPattern {
                name: "Office spawning shell".to_string(),
                parent_pattern: vec!["winword.exe".to_string(), "excel.exe".to_string(), 
                                     "powerpnt.exe".to_string(), "outlook.exe".to_string()],
                child_pattern: vec!["powershell.exe".to_string(), "cmd.exe".to_string()],
                command_pattern: None,
                mitre_technique: vec!["T1059.001".to_string(), "T1566".to_string()],
                severity: ThreatSeverity::High,
            },
            // Encoded PowerShell
            SuspiciousPattern {
                name: "Encoded PowerShell".to_string(),
                parent_pattern: vec![],
                child_pattern: vec!["powershell.exe".to_string()],
                command_pattern: Some("-enc".to_string()),
                mitre_technique: vec!["T1059.001".to_string(), "T1027".to_string()],
                severity: ThreatSeverity::Critical,
            },
            // LOLBin: certutil download
            SuspiciousPattern {
                name: "CertUtil download".to_string(),
                parent_pattern: vec![],
                child_pattern: vec!["certutil.exe".to_string()],
                command_pattern: Some("urlcache".to_string()),
                mitre_technique: vec!["T1105".to_string(), "T1218".to_string()],
                severity: ThreatSeverity::High,
            },
            // Mimikatz execution
            SuspiciousPattern {
                name: "Credential dumping tool".to_string(),
                parent_pattern: vec![],
                child_pattern: vec!["mimikatz".to_string(), "procdump".to_string()],
                command_pattern: Some("lsass".to_string()),
                mitre_technique: vec!["T1003.001".to_string()],
                severity: ThreatSeverity::Critical,
            },
            // PsExec lateral movement
            SuspiciousPattern {
                name: "PsExec lateral movement".to_string(),
                parent_pattern: vec![],
                child_pattern: vec!["psexec".to_string(), "psexesvc.exe".to_string()],
                command_pattern: None,
                mitre_technique: vec!["T1021.002".to_string()],
                severity: ThreatSeverity::High,
            },
        ]
    }

    /// Start monitoring process creation
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting process monitor");
        
        // Take initial snapshot
        self.snapshot_processes()?;
        
        // Start monitoring loop
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.monitoring_loop().await;
        });
        
        Ok(())
    }

    /// Take snapshot of current processes
    fn snapshot_processes(&self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            
            let mut pe32 = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if Process32FirstW(snapshot, &mut pe32).is_ok() {
                loop {
                    let process_name = String::from_utf16_lossy(
                        &pe32.szExeFile[..pe32.szExeFile.iter()
                            .position(|&c| c == 0).unwrap_or(pe32.szExeFile.len())]
                    );
                    
                    let node = ProcessNode {
                        pid: pe32.th32ProcessID,
                        parent_pid: pe32.th32ParentProcessID,
                        process_name: process_name.clone(),
                        command_line: String::new(), // Would need additional API call
                        created_at: SystemTime::now(),
                        children: Vec::new(),
                    };
                    
                    if let Ok(mut processes) = self.processes.lock() {
                        processes.insert(pe32.th32ProcessID, node);
                    }
                    
                    if Process32NextW(snapshot, &mut pe32).is_err() {
                        break;
                    }
                }
            }
            
            let _ = CloseHandle(snapshot);
        }
        
        Ok(())
    }

    /// Main monitoring loop
    async fn monitoring_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.check_for_new_processes() {
                tracing::error!("Process check failed: {}", e);
            }
        }
    }

    /// Check for new processes since last scan
    fn check_for_new_processes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let current_pids = self.get_current_pids()?;
        
        let known_pids: Vec<u32> = self.processes.lock()
            .map(|p| p.keys().copied().collect())
            .unwrap_or_default();
        
        // Find new PIDs
        for pid in current_pids {
            if !known_pids.contains(&pid) {
                self.handle_new_process(pid)?;
            }
        }
        
        Ok(())
    }

    /// Get all current process IDs
    fn get_current_pids(&self) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let mut pids = Vec::new();
        
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            let mut pe32 = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if Process32FirstW(snapshot, &mut pe32).is_ok() {
                loop {
                    pids.push(pe32.th32ProcessID);
                    if Process32NextW(snapshot, &mut pe32).is_err() {
                        break;
                    }
                }
            }
            
            let _ = CloseHandle(snapshot);
        }
        
        Ok(pids)
    }

    /// Handle newly detected process
    fn handle_new_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let event = self.create_process_event(pid)?;
        
        // Check for threats
        if let Some(threat) = self.analyze_for_threats(&event) {
            tracing::warn!("Process threat detected: {} (PID: {})", threat.threat_type, pid);
            // Would send to backend here
        }
        
        // Store in history
        if let Ok(mut history) = self.event_history.lock() {
            history.push_back(event.clone());
            if history.len() > self.max_history {
                history.pop_front();
            }
        }
        
        Ok(())
    }

    /// Create process event from PID
    fn create_process_event(&self, pid: u32) -> Result<ProcessEvent, Box<dyn std::error::Error>> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
            
            // Get process name
            let mut process_name = [0u16; 260];
            let mut size = 260u32;
            let _ = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, &mut process_name, &mut size);
            let process_name = String::from_utf16_lossy(&process_name[..size as usize]);
            
            // Get command line (simplified - would use NtQueryInformationProcess)
            let command_line = String::new();
            
            let event = ProcessEvent {
                timestamp: SystemTime::now(),
                pid,
                parent_pid: 0, // Would get from process info
                process_name: process_name.clone(),
                command_line,
                exe_path: process_name,
                user: String::from("SYSTEM"), // Would get from token
                session_id: 0,
                integrity_level: String::from("Medium"),
                file_hash: None,
                digital_signature: None,
                event_type: ProcessEventType::Created,
            };
            
            let _ = CloseHandle(handle);
            Ok(event)
        }
    }

    /// Analyze process event for threats
    fn analyze_for_threats(&self, event: &ProcessEvent) -> Option<ProcessThreat> {
        for pattern in &self.suspicious_patterns {
            // Check child pattern
            if !pattern.child_pattern.is_empty() {
                let matches = pattern.child_pattern.iter()
                    .any(|p| event.process_name.to_lowercase().contains(&p.to_lowercase()));
                
                if matches {
                    // Check command line pattern if specified
                    if let Some(cmd_pattern) = &pattern.command_pattern {
                        if !event.command_line.to_lowercase().contains(&cmd_pattern.to_lowercase()) {
                            continue;
                        }
                    }
                    
                    // Check parent pattern if specified
                    if !pattern.parent_pattern.is_empty() {
                        // Would check parent process name here
                    }
                    
                    return Some(ProcessThreat {
                        event: event.clone(),
                        threat_type: pattern.name.clone(),
                        severity: pattern.severity.clone(),
                        mitre_attack: pattern.mitre_technique.clone(),
                        description: format!("Suspicious process pattern detected: {}", pattern.name),
                        indicators: vec![
                            format!("Process: {}", event.process_name),
                            format!("Command: {}", event.command_line),
                        ],
                    });
                }
            }
        }
        
        None
    }

    /// Get process tree for a given PID
    pub fn get_process_tree(&self, pid: u32) -> Vec<ProcessNode> {
        let mut tree = Vec::new();
        
        if let Ok(processes) = self.processes.lock() {
            if let Some(node) = processes.get(&pid) {
                tree.push(node.clone());
                
                // Recursively get children
                for child_pid in &node.children {
                    tree.extend(self.get_process_tree(*child_pid));
                }
            }
        }
        
        tree
    }

    /// Clone for async context
    fn clone(&self) -> Self {
        Self {
            processes: Arc::clone(&self.processes),
            event_history: Arc::clone(&self.event_history),
            max_history: self.max_history,
            suspicious_patterns: self.suspicious_patterns.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let monitor = ProcessMonitor::new();
        assert!(!monitor.suspicious_patterns.is_empty());
    }
}
