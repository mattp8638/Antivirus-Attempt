//! Memory Scanner Module
//!
//! Scans process memory for malicious patterns, shellcode, and in-memory threats
//! Uses YARA rules and heuristic analysis
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::Debug::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryThreat {
    pub pid: u32,
    pub process_name: String,
    pub threat_type: MemoryThreatType,
    pub address: u64,
    pub size: usize,
    pub protection: String,
    pub indicators: Vec<String>,
    pub mitre_attack: Vec<String>,
    pub severity: ThreatSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryThreatType {
    Shellcode,
    InjectedCode,
    CobaltStrikeBeacon,
    MetasploitPayload,
    ReflectiveDLL,
    SuspiciousRWX,
    PEInMemory,
    HighEntropy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct MemoryRegion {
    base_address: u64,
    size: usize,
    protection: u32,
    state: u32,
    region_type: u32,
}

pub struct MemoryScanner {
    scan_interval: std::time::Duration,
    target_processes: Arc<Mutex<Vec<u32>>>,
    threat_patterns: Vec<ThreatPattern>,
}

#[derive(Debug, Clone)]
struct ThreatPattern {
    name: String,
    pattern: Vec<u8>,
    mask: Option<Vec<u8>>,
    threat_type: MemoryThreatType,
    mitre: Vec<String>,
}

impl MemoryScanner {
    pub fn new() -> Self {
        let patterns = Self::init_patterns();
        
        Self {
            scan_interval: std::time::Duration::from_secs(300), // 5 minutes
            target_processes: Arc::new(Mutex::new(Vec::new())),
            threat_patterns: patterns,
        }
    }

    fn init_patterns() -> Vec<ThreatPattern> {
        vec![
            // NOP sled (shellcode indicator)
            ThreatPattern {
                name: "NOP Sled".to_string(),
                pattern: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
                mask: None,
                threat_type: MemoryThreatType::Shellcode,
                mitre: vec!["T1055".to_string()],
            },
            // GetProcAddress call (API resolution)
            ThreatPattern {
                name: "GetProcAddress Call".to_string(),
                pattern: vec![0xFF, 0x15], // call [GetProcAddress]
                mask: Some(vec![0xFF, 0xFF]),
                threat_type: MemoryThreatType::Shellcode,
                mitre: vec!["T1055".to_string()],
            },
            // MZ header (PE in memory)
            ThreatPattern {
                name: "PE Header".to_string(),
                pattern: vec![0x4D, 0x5A], // MZ
                mask: None,
                threat_type: MemoryThreatType::PEInMemory,
                mitre: vec!["T1055".to_string()],
            },
            // Cobalt Strike beacon signature
            ThreatPattern {
                name: "Cobalt Strike Beacon".to_string(),
                pattern: vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x02],
                mask: None,
                threat_type: MemoryThreatType::CobaltStrikeBeacon,
                mitre: vec!["T1071.001".to_string(), "T1573".to_string()],
            },
            // Metasploit Meterpreter signature
            ThreatPattern {
                name: "Meterpreter".to_string(),
                pattern: b"metsrv".to_vec(),
                mask: None,
                threat_type: MemoryThreatType::MetasploitPayload,
                mitre: vec!["T1071.001".to_string()],
            },
        ]
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting memory scanner");
        
        let scanner = self.clone();
        tokio::spawn(async move {
            scanner.scanning_loop().await;
        });
        
        Ok(())
    }

    async fn scanning_loop(&self) {
        let mut interval = tokio::time::interval(self.scan_interval);
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.scan_all_processes() {
                tracing::error!("Memory scan failed: {}", e);
            }
        }
    }

    fn scan_all_processes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let processes = self.get_running_processes()?;
        
        for pid in processes {
            if let Err(e) = self.scan_process_and_report(pid) {
                tracing::debug!("Failed to scan PID {}: {}", pid, e);
            }
        }
        
        Ok(())
    }

    pub fn scan_pid_collect(&self, pid: u32) -> Result<Vec<MemoryThreat>, Box<dyn std::error::Error>> {
        self.scan_process_collect(pid)
    }

    pub fn scan_all_collect(&self) -> Result<Vec<MemoryThreat>, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        let pids = self.get_running_processes()?;
        for pid in pids {
            if let Ok(mut threats) = self.scan_process_collect(pid) {
                out.append(&mut threats);
            }
        }
        Ok(out)
    }

    fn get_running_processes(&self) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        
        let mut pids = Vec::new();
        
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            let mut pe32 = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if Process32FirstW(snapshot, &mut pe32).is_ok() {
                loop {
                    if pe32.th32ProcessID > 4 { // Skip system processes
                        pids.push(pe32.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut pe32).is_err() {
                        break;
                    }
                }
            }
            
            let _ = CloseHandle(snapshot);
        }
        
        Ok(pids)
    }

    fn scan_process_and_report(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let threats = self.scan_process_collect(pid)?;
        for threat in threats {
            tracing::warn!(
                "Memory threat detected in PID {}: {:?}",
                pid,
                threat.threat_type
            );
        }
        Ok(())
    }

    fn scan_process_collect(&self, pid: u32) -> Result<Vec<MemoryThreat>, Box<dyn std::error::Error>> {
        let mut threats = Vec::new();

        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid
            )?;
            
            // Enumerate memory regions
            let regions = self.enumerate_memory_regions(handle)?;
            
            // Scan each region
            for region in regions {
                if let Some(threat) = self.scan_memory_region(handle, &region, pid)? {
                    threats.push(threat);
                }
            }
            
            let _ = CloseHandle(handle);
        }
        
        Ok(threats)
    }

    unsafe fn enumerate_memory_regions(&self, handle: HANDLE) -> Result<Vec<MemoryRegion>, Box<dyn std::error::Error>> {
        let mut regions = Vec::new();
        let mut address = 0u64;
        
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            );
            
            if result == 0 {
                break;
            }
            
            // Only scan committed, private memory that's executable or writable
            if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE {
                let is_executable = (mbi.Protect.0 & PAGE_EXECUTE.0) != 0 ||
                                   (mbi.Protect.0 & PAGE_EXECUTE_READ.0) != 0 ||
                                   (mbi.Protect.0 & PAGE_EXECUTE_READWRITE.0) != 0;
                
                if is_executable {
                    regions.push(MemoryRegion {
                        base_address: mbi.BaseAddress as u64,
                        size: mbi.RegionSize,
                        protection: mbi.Protect.0,
                        state: mbi.State.0,
                        region_type: mbi.Type.0,
                    });
                }
            }
            
            address = (mbi.BaseAddress as u64) + (mbi.RegionSize as u64);
        }
        
        Ok(regions)
    }

    unsafe fn scan_memory_region(
        &self,
        handle: HANDLE,
        region: &MemoryRegion,
        pid: u32
    ) -> Result<Option<MemoryThreat>, Box<dyn std::error::Error>> {
        let process_name = self.get_process_name(pid);

        // Limit scan size to prevent excessive memory usage
        let max_read = std::cmp::min(region.size, 10 * 1024 * 1024); // 10MB max
        
        let mut buffer = vec![0u8; max_read];
        let mut bytes_read = 0usize;
        
        let success = ReadProcessMemory(
            handle,
            region.base_address as *const _,
            buffer.as_mut_ptr() as *mut _,
            max_read,
            Some(&mut bytes_read)
        );
        
        if success.is_err() || bytes_read == 0 {
            return Ok(None);
        }
        
        buffer.truncate(bytes_read);
        
        // Check for RWX (suspicious)
        if (region.protection & PAGE_EXECUTE_READWRITE.0) != 0 {
            if Self::is_known_jit_process(&process_name) {
                return Ok(None);
            }

            return Ok(Some(MemoryThreat {
                pid,
                process_name,
                threat_type: MemoryThreatType::SuspiciousRWX,
                address: region.base_address,
                size: region.size,
                protection: format!("RWX (0x{:X})", region.protection),
                indicators: vec!["RWX memory region detected".to_string()],
                mitre_attack: vec!["T1055".to_string()],
                severity: ThreatSeverity::High,
            }));
        }
        
        // Pattern matching
        for pattern in &self.threat_patterns {
            if self.contains_pattern(&buffer, &pattern.pattern) {
                return Ok(Some(MemoryThreat {
                    pid,
                    process_name: process_name.clone(),
                    threat_type: pattern.threat_type.clone(),
                    address: region.base_address,
                    size: region.size,
                    protection: format!("0x{:X}", region.protection),
                    indicators: vec![format!("Pattern matched: {}", pattern.name)],
                    mitre_attack: pattern.mitre.clone(),
                    severity: ThreatSeverity::Critical,
                }));
            }
        }
        
        // Entropy check for encrypted payloads
        let entropy = self.calculate_entropy(&buffer);
        if entropy > 7.5 { // Very high entropy
            return Ok(Some(MemoryThreat {
                pid,
                process_name,
                threat_type: MemoryThreatType::HighEntropy,
                address: region.base_address,
                size: region.size,
                protection: format!("0x{:X}", region.protection),
                indicators: vec![format!("High entropy: {:.2}", entropy)],
                mitre_attack: vec!["T1027".to_string()],
                severity: ThreatSeverity::Medium,
            }));
        }
        
        Ok(None)
    }

    fn contains_pattern(&self, haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    fn is_known_jit_process(process_name: &str) -> bool {
        let process = process_name.to_ascii_lowercase();
        [
            "dotnet.exe",
            "w3wp.exe",
            "powershell.exe",
            "pwsh.exe",
            "java.exe",
            "javaw.exe",
            "node.exe",
            "msedge.exe",
            "chrome.exe",
            "firefox.exe",
        ]
        .iter()
        .any(|known| process.ends_with(known))
    }

    fn get_process_name(&self, pid: u32) -> String {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return format!("process_{}", pid),
            };

            let mut name_buffer = vec![0u16; 2048];
            let mut buffer_len = name_buffer.len() as u32;

            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                PWSTR(name_buffer.as_mut_ptr()),
                &mut buffer_len,
            )
            .is_ok();

            let _ = CloseHandle(handle);

            if ok && buffer_len > 0 {
                let full_path = String::from_utf16_lossy(&name_buffer[..buffer_len as usize]);
                if let Some(file_name) = Path::new(&full_path).file_name().and_then(|v| v.to_str()) {
                    return file_name.to_string();
                }
                return full_path;
            }
        }

        format!("process_{}", pid)
    }

    fn clone(&self) -> Self {
        Self {
            scan_interval: self.scan_interval,
            target_processes: Arc::clone(&self.target_processes),
            threat_patterns: self.threat_patterns.clone(),
        }
    }
}
