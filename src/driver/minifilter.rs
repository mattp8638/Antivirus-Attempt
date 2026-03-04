//! File System Minifilter Driver Interface
//!
//! Monitors and controls file system operations:
//! - File create/open/read/write/delete
//! - Ransomware behavior detection
//! - Real-time file scanning
//! - File encryption/decryption monitoring
//!
//! Uses Windows Filter Manager (fltmgr.sys)
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};

/// File operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileOperationType {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename,
    SetInformation,
    QueryInformation,
}

/// File operation event from minifilter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub timestamp: SystemTime,
    pub process_id: u32,
    pub thread_id: u32,
    pub operation: FileOperationType,
    pub file_path: String,
    pub status: u32,
    pub bytes_transferred: u64,
    pub is_directory: bool,
}

/// Ransomware behavior indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIndicator {
    pub process_id: u32,
    pub process_name: String,
    pub files_encrypted: u32,
    pub file_extensions_changed: Vec<String>,
    pub file_types_targeted: Vec<String>,
    pub encryption_speed: f64, // files per second
    pub threat_score: f64,
    pub indicators: Vec<String>,
}

/// Process file activity tracking
#[derive(Debug, Clone)]
struct ProcessFileActivity {
    pid: u32,
    files_written: u32,
    files_deleted: u32,
    files_renamed: u32,
    extension_changes: HashMap<String, u32>,
    write_operations: VecDeque<SystemTime>,
    first_activity: SystemTime,
}

impl ProcessFileActivity {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            files_written: 0,
            files_deleted: 0,
            files_renamed: 0,
            extension_changes: HashMap::new(),
            write_operations: VecDeque::new(),
            first_activity: SystemTime::now(),
        }
    }

    fn add_write(&mut self) {
        self.files_written += 1;
        self.write_operations.push_back(SystemTime::now());
        
        // Keep only recent operations (last 10 seconds)
        let cutoff = SystemTime::now() - Duration::from_secs(10);
        while let Some(ts) = self.write_operations.front() {
            if *ts < cutoff {
                self.write_operations.pop_front();
            } else {
                break;
            }
        }
    }

    fn get_write_rate(&self) -> f64 {
        if self.write_operations.is_empty() {
            return 0.0;
        }
        
        if let (Some(first), Some(last)) = (self.write_operations.front(), self.write_operations.back()) {
            if let Ok(duration) = last.duration_since(*first) {
                let seconds = duration.as_secs_f64();
                if seconds > 0.0 {
                    return self.write_operations.len() as f64 / seconds;
                }
            }
        }
        
        0.0
    }
}

/// Minifilter manager
pub struct MinifilterManager {
    file_activities: Arc<Mutex<HashMap<u32, ProcessFileActivity>>>,
    ransomware_threshold: f64,
    monitored_extensions: Vec<String>,
}

impl MinifilterManager {
    pub fn new() -> Self {
        Self {
            file_activities: Arc::new(Mutex::new(HashMap::new())),
            ransomware_threshold: 10.0, // 10 files/second
            monitored_extensions: vec![
                "doc".to_string(), "docx".to_string(), "xls".to_string(), "xlsx".to_string(),
                "ppt".to_string(), "pptx".to_string(), "pdf".to_string(),
                "jpg".to_string(), "jpeg".to_string(), "png".to_string(), "gif".to_string(),
                "mp4".to_string(), "avi".to_string(), "mkv".to_string(),
                "zip".to_string(), "rar".to_string(), "7z".to_string(),
                "txt".to_string(), "log".to_string(), "db".to_string(), "sql".to_string(),
            ],
        }
    }

    /// Handle file operation from minifilter
    pub fn on_file_operation(&self, operation: FileOperation) {
        match operation.operation {
            FileOperationType::Write => {
                self.track_write_operation(&operation);
                self.check_ransomware_behavior(operation.process_id);
            }
            FileOperationType::Delete => {
                self.track_delete_operation(&operation);
            }
            FileOperationType::Rename => {
                self.track_rename_operation(&operation);
            }
            _ => {}
        }
    }

    fn track_write_operation(&self, operation: &FileOperation) {
        if let Ok(mut activities) = self.file_activities.lock() {
            let activity = activities.entry(operation.process_id)
                .or_insert_with(|| ProcessFileActivity::new(operation.process_id));
            
            activity.add_write();
        }
    }

    fn track_delete_operation(&self, operation: &FileOperation) {
        if let Ok(mut activities) = self.file_activities.lock() {
            let activity = activities.entry(operation.process_id)
                .or_insert_with(|| ProcessFileActivity::new(operation.process_id));
            
            activity.files_deleted += 1;
        }
    }

    fn track_rename_operation(&self, operation: &FileOperation) {
        if let Ok(mut activities) = self.file_activities.lock() {
            let activity = activities.entry(operation.process_id)
                .or_insert_with(|| ProcessFileActivity::new(operation.process_id));
            
            activity.files_renamed += 1;
            
            // Track extension changes (ransomware indicator)
            if let Some(ext) = Self::get_extension(&operation.file_path) {
                *activity.extension_changes.entry(ext.to_lowercase()).or_insert(0) += 1;
            }
        }
    }

    fn check_ransomware_behavior(&self, pid: u32) {
        if let Ok(activities) = self.file_activities.lock() {
            if let Some(activity) = activities.get(&pid) {
                let write_rate = activity.get_write_rate();
                
                // High write rate + multiple files = potential ransomware
                if write_rate > self.ransomware_threshold && activity.files_written > 50 {
                    let indicator = RansomwareIndicator {
                        process_id: pid,
                        process_name: format!("process_{}", pid),
                        files_encrypted: activity.files_written,
                        file_extensions_changed: activity.extension_changes.keys().cloned().collect(),
                        file_types_targeted: self.monitored_extensions.clone(),
                        encryption_speed: write_rate,
                        threat_score: self.calculate_threat_score(activity),
                        indicators: vec![
                            format!("High file write rate: {:.2} files/sec", write_rate),
                            format!("Total files modified: {}", activity.files_written),
                            format!("Files deleted: {}", activity.files_deleted),
                            format!("Extension changes: {}", activity.extension_changes.len()),
                        ],
                    };
                    
                    tracing::error!(
                        "RANSOMWARE DETECTED: PID {} - {:.2} files/sec, {} files encrypted",
                        pid, write_rate, activity.files_written
                    );
                    
                    // Would trigger immediate response here
                }
            }
        }
    }

    fn calculate_threat_score(&self, activity: &ProcessFileActivity) -> f64 {
        let mut score = 0.0;
        
        // High write rate
        score += (activity.get_write_rate() / self.ransomware_threshold) * 30.0;
        
        // Many files modified
        score += (activity.files_written as f64 / 100.0) * 25.0;
        
        // File deletions
        score += (activity.files_deleted as f64 / 50.0) * 20.0;
        
        // Extension changes (very suspicious)
        score += (activity.extension_changes.len() as f64) * 5.0;
        
        // Multiple renames (ransomware pattern)
        score += (activity.files_renamed as f64 / 50.0) * 20.0;
        
        score.min(100.0)
    }

    fn get_extension(path: &str) -> Option<String> {
        std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    }

    /// Block file operation (would send to kernel driver)
    pub fn block_file_operation(&self, pid: u32, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        tracing::warn!("Blocking file operation: PID {} -> {}", pid, file_path);
        
        // In production, would send IOCTL to driver to block operation
        
        Ok(())
    }

    /// Terminate ransomware process
    pub fn terminate_ransomware(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        tracing::error!("Terminating ransomware process: PID {}", pid);
        
        unsafe {
            use windows::Win32::System::Threading::*;
            
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
            let _ = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
        }
        
        Ok(())
    }
}
