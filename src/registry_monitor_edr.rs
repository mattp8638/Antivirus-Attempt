//! Registry Monitor Module
//!
//! Monitors Windows Registry for persistence mechanisms and suspicious changes
//!
//! Author: TamsilCMS Security Team  
//! Date: 2026-02-10

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::*;
use windows::core::PCWSTR;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryThreat {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub threat_type: RegistryThreatType,
    pub change_type: ChangeType,
    pub mitre_attack: Vec<String>,
    pub severity: ThreatSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryThreatType {
    RunKeyPersistence,
    IFEOHijack,
    WinlogonModification,
    AppInitDLL,
    FileAssociationHijack,
    DefenderExclusion,
    ServiceCreation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct MonitoredKey {
    hive: HKEY,
    path: String,
    threat_type: RegistryThreatType,
    mitre: Vec<String>,
}

pub struct RegistryMonitor {
    monitored_keys: Vec<MonitoredKey>,
    baseline: Arc<Mutex<HashMap<String, HashMap<String, String>>>>,
    check_interval: std::time::Duration,
}

impl RegistryMonitor {
    pub fn new() -> Self {
        let keys = Self::init_monitored_keys();
        
        Self {
            monitored_keys: keys,
            baseline: Arc::new(Mutex::new(HashMap::new())),
            check_interval: std::time::Duration::from_secs(5),
        }
    }

    fn init_monitored_keys() -> Vec<MonitoredKey> {
        vec![
            // Run keys persistence
            MonitoredKey {
                hive: HKEY_CURRENT_USER,
                path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                threat_type: RegistryThreatType::RunKeyPersistence,
                mitre: vec!["T1547.001".to_string()],
            },
            MonitoredKey {
                hive: HKEY_LOCAL_MACHINE,
                path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
                threat_type: RegistryThreatType::RunKeyPersistence,
                mitre: vec!["T1547.001".to_string()],
            },
            // Winlogon
            MonitoredKey {
                hive: HKEY_LOCAL_MACHINE,
                path: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".to_string(),
                threat_type: RegistryThreatType::WinlogonModification,
                mitre: vec!["T1547.001".to_string()],
            },
            // IFEO
            MonitoredKey {
                hive: HKEY_LOCAL_MACHINE,
                path: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".to_string(),
                threat_type: RegistryThreatType::IFEOHijack,
                mitre: vec!["T1546.012".to_string()],
            },
            // AppInit DLLs
            MonitoredKey {
                hive: HKEY_LOCAL_MACHINE,
                path: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows".to_string(),
                threat_type: RegistryThreatType::AppInitDLL,
                mitre: vec!["T1546.010".to_string()],
            },
            // Windows Defender exclusions
            MonitoredKey {
                hive: HKEY_LOCAL_MACHINE,
                path: r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths".to_string(),
                threat_type: RegistryThreatType::DefenderExclusion,
                mitre: vec!["T1562.001".to_string()],
            },
        ]
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting registry monitor");
        
        // Take baseline
        self.create_baseline()?;
        
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.monitoring_loop().await;
        });
        
        Ok(())
    }

    fn create_baseline(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut baseline = self.baseline.lock().unwrap();
        
        for key in &self.monitored_keys {
            if let Ok(values) = self.read_registry_key(key.hive, &key.path) {
                baseline.insert(key.path.clone(), values);
            }
        }
        
        tracing::info!("Registry baseline created for {} keys", baseline.len());
        Ok(())
    }

    async fn monitoring_loop(&self) {
        let mut interval = tokio::time::interval(self.check_interval);
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.check_for_changes() {
                tracing::error!("Registry check failed: {}", e);
            }
        }
    }

    fn check_for_changes(&self) -> Result<(), Box<dyn std::error::Error>> {
        for key in &self.monitored_keys {
            match self.read_registry_key(key.hive, &key.path) {
                Ok(current_values) => {
                    if let Some(threats) = self.compare_with_baseline(&key.path, &current_values, key) {
                        for threat in threats {
                            tracing::warn!("Registry threat: {:?} at {}", threat.threat_type, threat.key_path);
                            // Would report to backend here
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to read {}: {}", key.path, e);
                }
            }
        }
        
        Ok(())
    }

    fn read_registry_key(&self, hive: HKEY, path: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut values = HashMap::new();
        
        unsafe {
            let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey = HKEY::default();
            
            let result = RegOpenKeyExW(
                hive,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey
            );
            
            if result.is_err() {
                return Err("Failed to open key".into());
            }
            
            // Enumerate values
            let mut index = 0u32;
            loop {
                let mut name_buf = [0u16; 260];
                let mut name_len = 260u32;
                let mut data_buf = [0u8; 1024];
                let mut data_len = 1024u32;
                let mut value_type = REG_NONE;
                
                let result = RegEnumValueW(
                    hkey,
                    index,
                    &mut name_buf,
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len)
                );
                
                if result.is_err() {
                    break;
                }
                
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let data = String::from_utf8_lossy(&data_buf[..data_len as usize]).to_string();
                
                values.insert(name, data);
                index += 1;
            }
            
            let _ = RegCloseKey(hkey);
        }
        
        Ok(values)
    }

    fn compare_with_baseline(
        &self,
        key_path: &str,
        current: &HashMap<String, String>,
        monitored_key: &MonitoredKey
    ) -> Option<Vec<RegistryThreat>> {
        let baseline = self.baseline.lock().unwrap();
        let baseline_values = baseline.get(key_path)?;
        
        let mut threats = Vec::new();
        
        // Check for new/modified values
        for (name, value) in current {
            let change_type = if !baseline_values.contains_key(name) {
                ChangeType::Created
            } else if baseline_values.get(name) != Some(value) {
                ChangeType::Modified
            } else {
                continue; // No change
            };
            
            // Check if change is suspicious
            if self.is_suspicious_change(monitored_key, name, value) {
                threats.push(RegistryThreat {
                    key_path: key_path.to_string(),
                    value_name: name.clone(),
                    value_data: value.clone(),
                    threat_type: monitored_key.threat_type.clone(),
                    change_type,
                    mitre_attack: monitored_key.mitre.clone(),
                    severity: ThreatSeverity::High,
                    description: format!("Suspicious registry change detected in {}", key_path),
                });
            }
        }
        
        // Check for deleted values
        for name in baseline_values.keys() {
            if !current.contains_key(name) {
                threats.push(RegistryThreat {
                    key_path: key_path.to_string(),
                    value_name: name.clone(),
                    value_data: String::new(),
                    threat_type: monitored_key.threat_type.clone(),
                    change_type: ChangeType::Deleted,
                    mitre_attack: monitored_key.mitre.clone(),
                    severity: ThreatSeverity::Medium,
                    description: format!("Registry value deleted from {}", key_path),
                });
            }
        }
        
        if threats.is_empty() { None } else { Some(threats) }
    }

    fn is_suspicious_change(&self, key: &MonitoredKey, _name: &str, value: &str) -> bool {
        let value_lower = value.to_lowercase();
        
        // Suspicious paths
        let suspicious_paths = [
            "temp", "appdata", "downloads", "public", "programdata",
            "powershell", "cmd.exe", "wscript", "cscript"
        ];
        
        if suspicious_paths.iter().any(|p| value_lower.contains(p)) {
            return true;
        }
        
        // Suspicious based on threat type
        match key.threat_type {
            RegistryThreatType::DefenderExclusion => true, // Any exclusion is suspicious
            _ => false,
        }
    }

    fn clone(&self) -> Self {
        Self {
            monitored_keys: self.monitored_keys.clone(),
            baseline: Arc::clone(&self.baseline),
            check_interval: self.check_interval,
        }
    }
}
