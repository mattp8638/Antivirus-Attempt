//! Network Filter Driver Interface
//!
//! Packet-level network monitoring and filtering:
//! - Deep packet inspection (DPI)
//! - C2 traffic detection
//! - Protocol analysis
//! - Connection blocking
//!
//! Uses Windows Filtering Platform (WFP) and NDIS
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Network protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

/// Network flow direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

/// Network packet metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: SystemTime,
    pub process_id: u32,
    pub protocol: Protocol,
    pub direction: FlowDirection,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub payload_size: usize,
    pub flags: u16,
}

/// Network threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreat {
    pub threat_type: NetworkThreatType,
    pub process_id: u32,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub indicators: Vec<String>,
    pub mitre_attack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkThreatType {
    C2Communication,
    PortScanning,
    DNSTunneling,
    DataExfiltration,
    LateralMovement,
    SuspiciousProtocol,
}

/// Connection state tracking
#[derive(Debug, Clone)]
struct ConnectionState {
    process_id: u32,
    remote_addr: String,
    remote_port: u16,
    protocol: Protocol,
    established_at: SystemTime,
    bytes_sent: u64,
    bytes_received: u64,
    packet_count: u32,
}

/// Network filter manager
pub struct NetworkFilterManager {
    active_connections: Arc<Mutex<HashMap<String, ConnectionState>>>,
    blocked_ips: Arc<Mutex<HashSet<String>>>,
    c2_indicators: Vec<C2Indicator>,
}

#[derive(Debug, Clone)]
struct C2Indicator {
    pattern: String,
    ports: Vec<u16>,
    protocol: Protocol,
}

impl NetworkFilterManager {
    pub fn new() -> Self {
        Self {
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            blocked_ips: Arc::new(Mutex::new(HashSet::new())),
            c2_indicators: Self::init_c2_indicators(),
        }
    }

    fn init_c2_indicators() -> Vec<C2Indicator> {
        vec![
            C2Indicator {
                pattern: "cobalt_strike".to_string(),
                ports: vec![80, 443, 8080, 50050],
                protocol: Protocol::TCP,
            },
            C2Indicator {
                pattern: "metasploit".to_string(),
                ports: vec![4444, 4445, 5555],
                protocol: Protocol::TCP,
            },
            C2Indicator {
                pattern: "empire".to_string(),
                ports: vec![80, 443],
                protocol: Protocol::TCP,
            },
        ]
    }

    /// Handle network packet from WFP filter
    pub fn on_packet(&self, packet: PacketInfo) -> FilterAction {
        // Check if IP is blocked
        if self.is_blocked(&packet.remote_addr) {
            tracing::warn!(
                "Blocked connection attempt to: {} (PID {})",
                packet.remote_addr,
                packet.process_id
            );
            return FilterAction::Block;
        }

        // Update connection state
        self.update_connection_state(&packet);

        // Analyze for threats
        if let Some(threat) = self.analyze_packet(&packet) {
            self.handle_threat(threat);
            return FilterAction::Block;
        }

        FilterAction::Allow
    }

    fn update_connection_state(&self, packet: &PacketInfo) {
        let key = format!("{}:{}:{}", packet.process_id, packet.remote_addr, packet.remote_port);
        
        if let Ok(mut conns) = self.active_connections.lock() {
            let state = conns.entry(key).or_insert_with(|| ConnectionState {
                process_id: packet.process_id,
                remote_addr: packet.remote_addr.clone(),
                remote_port: packet.remote_port,
                protocol: packet.protocol,
                established_at: SystemTime::now(),
                bytes_sent: 0,
                bytes_received: 0,
                packet_count: 0,
            });

            match packet.direction {
                FlowDirection::Outbound => state.bytes_sent += packet.payload_size as u64,
                FlowDirection::Inbound => state.bytes_received += packet.payload_size as u64,
            }
            state.packet_count += 1;
        }
    }

    fn analyze_packet(&self, packet: &PacketInfo) -> Option<NetworkThreat> {
        // Check for suspicious ports
        if self.is_suspicious_port(packet.remote_port) {
            return Some(NetworkThreat {
                threat_type: NetworkThreatType::C2Communication,
                process_id: packet.process_id,
                remote_addr: packet.remote_addr.clone(),
                remote_port: packet.remote_port,
                protocol: packet.protocol,
                indicators: vec![format!("Suspicious port: {}", packet.remote_port)],
                mitre_attack: vec!["T1071".to_string()],
            });
        }

        // Check for lateral movement
        if self.is_lateral_movement(packet) {
            return Some(NetworkThreat {
                threat_type: NetworkThreatType::LateralMovement,
                process_id: packet.process_id,
                remote_addr: packet.remote_addr.clone(),
                remote_port: packet.remote_port,
                protocol: packet.protocol,
                indicators: vec!["SMB/RDP/WinRM connection to internal host".to_string()],
                mitre_attack: vec!["T1021".to_string()],
            });
        }

        // Check for data exfiltration
        if self.is_data_exfiltration(packet) {
            return Some(NetworkThreat {
                threat_type: NetworkThreatType::DataExfiltration,
                process_id: packet.process_id,
                remote_addr: packet.remote_addr.clone(),
                remote_port: packet.remote_port,
                protocol: packet.protocol,
                indicators: vec!["Large data transfer detected".to_string()],
                mitre_attack: vec!["T1041".to_string()],
            });
        }

        None
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        let suspicious_ports = [4444, 4445, 5555, 31337, 6666, 6667];
        suspicious_ports.contains(&port)
    }

    fn is_lateral_movement(&self, packet: &PacketInfo) -> bool {
        let lateral_ports = [445, 3389, 5985, 5986]; // SMB, RDP, WinRM
        lateral_ports.contains(&packet.remote_port) && 
            Self::is_internal_ip(&packet.remote_addr)
    }

    fn is_data_exfiltration(&self, packet: &PacketInfo) -> bool {
        // Check connection state for large uploads
        let key = format!("{}:{}:{}", packet.process_id, packet.remote_addr, packet.remote_port);
        
        if let Ok(conns) = self.active_connections.lock() {
            if let Some(state) = conns.get(&key) {
                // Large outbound traffic
                return state.bytes_sent > 100_000_000; // 100MB
            }
        }
        
        false
    }

    fn is_internal_ip(ip: &str) -> bool {
        ip.starts_with("10.") ||
        ip.starts_with("192.168.") ||
        (ip.starts_with("172.") && ip.split('.').nth(1)
            .and_then(|s| s.parse::<u8>().ok())
            .map(|n| n >= 16 && n <= 31)
            .unwrap_or(false))
    }

    fn handle_threat(&self, threat: NetworkThreat) {
        tracing::error!(
            "Network threat detected: {:?} from PID {} to {}:{}",
            threat.threat_type,
            threat.process_id,
            threat.remote_addr,
            threat.remote_port
        );

        // Block the IP
        self.block_ip(&threat.remote_addr);
    }

    fn is_blocked(&self, ip: &str) -> bool {
        if let Ok(blocked) = self.blocked_ips.lock() {
            blocked.contains(ip)
        } else {
            false
        }
    }

    /// Block IP address
    pub fn block_ip(&self, ip: &str) {
        if let Ok(mut blocked) = self.blocked_ips.lock() {
            blocked.insert(ip.to_string());
            tracing::warn!("Blocked IP: {}", ip);
        }
    }

    /// Unblock IP address
    pub fn unblock_ip(&self, ip: &str) {
        if let Ok(mut blocked) = self.blocked_ips.lock() {
            blocked.remove(ip);
            tracing::info!("Unblocked IP: {}", ip);
        }
    }
}

/// Filter action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Block,
    Inspect,
}
