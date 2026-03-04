//! Network Monitor Module
//!
//! Monitors network connections for C2 communication, beaconing, and lateral movement
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreat {
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub threat_type: NetworkThreatType,
    pub mitre_attack: Vec<String>,
    pub severity: ThreatSeverity,
    pub description: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkThreatType {
    SuspiciousPort,
    NonBrowserHTTPS,
    C2Beaconing,
    LateralMovement,
    PortScanning,
    DGADomain,
    DNSTunneling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct ConnectionEvent {
    timestamp: SystemTime,
    pid: u32,
    remote_addr: String,
    remote_port: u16,
}

#[derive(Debug, Clone)]
struct BeaconPattern {
    pid: u32,
    remote: String,
    intervals: Vec<Duration>,
    count: u32,
}

pub struct NetworkMonitor {
    connections: Arc<Mutex<HashMap<u32, Vec<ConnectionEvent>>>>,
    beacon_candidates: Arc<Mutex<HashMap<(u32, String), VecDeque<SystemTime>>>>,
    c2_ports: HashMap<u16, String>,
    lateral_ports: Vec<u16>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let c2_ports = Self::init_c2_ports();
        
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            beacon_candidates: Arc::new(Mutex::new(HashMap::new())),
            c2_ports,
            lateral_ports: vec![445, 3389, 5985, 5986], // SMB, RDP, WinRM
        }
    }

    fn init_c2_ports() -> HashMap<u16, String> {
        let mut ports = HashMap::new();
        ports.insert(4444, "Metasploit default".to_string());
        ports.insert(5555, "Metasploit alternate".to_string());
        ports.insert(8080, "Common C2".to_string());
        ports.insert(8443, "Common HTTPS C2".to_string());
        ports.insert(31337, "Elite port".to_string());
        ports
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting network monitor");
        
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.connection_monitoring_loop().await;
        });
        
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.beaconing_detection_loop().await;
        });
        
        Ok(())
    }

    async fn connection_monitoring_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.check_connections() {
                tracing::error!("Connection check failed: {}", e);
            }
        }
    }

    async fn beaconing_detection_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            self.detect_beaconing();
        }
    }

    fn check_connections(&self) -> Result<(), Box<dyn std::error::Error>> {
        // This would use netstat or Windows API to get connections
        // Simplified implementation
        Ok(())
    }

    fn analyze_connection(
        &self,
        pid: u32,
        process_name: &str,
        remote_addr: &str,
        remote_port: u16
    ) -> Option<NetworkThreat> {
        let mut indicators = Vec::new();
        
        // Check for suspicious port
        if let Some(description) = self.c2_ports.get(&remote_port) {
            indicators.push(format!("Known C2 port: {}", description));
            return Some(NetworkThreat {
                pid,
                process_name: process_name.to_string(),
                local_addr: "0.0.0.0".to_string(),
                remote_addr: remote_addr.to_string(),
                remote_port,
                threat_type: NetworkThreatType::SuspiciousPort,
                mitre_attack: vec!["T1071".to_string()],
                severity: ThreatSeverity::High,
                description: format!("Connection to suspicious port {}", remote_port),
                indicators,
            });
        }
        
        // Check for non-browser HTTPS
        if remote_port == 443 {
            let browsers = ["chrome", "firefox", "edge", "safari"];
            let is_browser = browsers.iter().any(|b| process_name.to_lowercase().contains(b));
            
            if !is_browser {
                indicators.push("Non-browser HTTPS connection".to_string());
                return Some(NetworkThreat {
                    pid,
                    process_name: process_name.to_string(),
                    local_addr: "0.0.0.0".to_string(),
                    remote_addr: remote_addr.to_string(),
                    remote_port,
                    threat_type: NetworkThreatType::NonBrowserHTTPS,
                    mitre_attack: vec!["T1071.001".to_string()],
                    severity: ThreatSeverity::Medium,
                    description: "Non-browser process making HTTPS connection".to_string(),
                    indicators,
                });
            }
        }
        
        // Check for lateral movement
        if self.lateral_ports.contains(&remote_port) && Self::is_internal_ip(remote_addr) {
            indicators.push(format!("Lateral movement port: {}", remote_port));
            return Some(NetworkThreat {
                pid,
                process_name: process_name.to_string(),
                local_addr: "0.0.0.0".to_string(),
                remote_addr: remote_addr.to_string(),
                remote_port,
                threat_type: NetworkThreatType::LateralMovement,
                mitre_attack: vec!["T1021".to_string()],
                severity: ThreatSeverity::High,
                description: "Potential lateral movement detected".to_string(),
                indicators,
            });
        }
        
        // Track for beaconing analysis
        let key = (pid, format!("{}:{}", remote_addr, remote_port));
        if let Ok(mut candidates) = self.beacon_candidates.lock() {
            candidates.entry(key)
                .or_insert_with(VecDeque::new)
                .push_back(SystemTime::now());
        }
        
        None
    }

    fn detect_beaconing(&self) {
        let mut candidates = self.beacon_candidates.lock().unwrap();
        let now = SystemTime::now();
        let cutoff = now - Duration::from_secs(3600); // 1 hour window
        
        for ((pid, remote), timestamps) in candidates.iter_mut() {
            // Remove old timestamps
            while let Some(ts) = timestamps.front() {
                if *ts < cutoff {
                    timestamps.pop_front();
                } else {
                    break;
                }
            }
            
            if timestamps.len() < 5 {
                continue;
            }
            
            // Calculate intervals
            let mut intervals = Vec::new();
            for i in 1..timestamps.len() {
                if let Ok(duration) = timestamps[i].duration_since(timestamps[i-1]) {
                    intervals.push(duration);
                }
            }
            
            if Self::is_beaconing_pattern(&intervals) {
                tracing::warn!("C2 beaconing detected: PID {} -> {}", pid, remote);
                // Would report threat here
            }
        }
    }

    fn is_beaconing_pattern(intervals: &[Duration]) -> bool {
        if intervals.len() < 4 {
            return false;
        }
        
        let secs: Vec<f64> = intervals.iter().map(|d| d.as_secs_f64()).collect();
        let mean = secs.iter().sum::<f64>() / secs.len() as f64;
        
        // Calculate standard deviation
        let variance = secs.iter()
            .map(|s| (s - mean).powi(2))
            .sum::<f64>() / secs.len() as f64;
        let std_dev = variance.sqrt();
        
        // Coefficient of variation
        let cv = std_dev / mean;
        
        // Beaconing: regular interval (10s - 10min), low variation (<20%)
        mean >= 10.0 && mean <= 600.0 && cv < 0.2
    }

    fn is_internal_ip(ip: &str) -> bool {
        ip.starts_with("10.") ||
        ip.starts_with("192.168.") ||
        (ip.starts_with("172.") && ip.split('.').nth(1)
            .and_then(|s| s.parse::<u8>().ok())
            .map(|n| n >= 16 && n <= 31)
            .unwrap_or(false))
    }

    fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            beacon_candidates: Arc::clone(&self.beacon_candidates),
            c2_ports: self.c2_ports.clone(),
            lateral_ports: self.lateral_ports.clone(),
        }
    }
}
