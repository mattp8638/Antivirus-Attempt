//! TamsilCMS Sentinel EDR Library
//!
//! Core detection and prevention modules for enterprise endpoint security.
//!
//! # Modules
//!
//! - `etw_monitor` - Event Tracing for Windows integration
//! - `amsi_integration` - Antimalware Scan Interface
//! - `driver` - Kernel driver communication
//! - `ml_threat_scoring` - Machine learning threat detection
//! - `threat_intelligence_feeds` - IOC feeds integration
//! - `boot_protection` - UEFI/ELAM/TPM protection
//! - `code_signing` - Authenticode verification

pub mod etw_monitor;
pub mod amsi_integration;
pub mod driver;
pub mod ml_threat_scoring;
pub mod threat_intelligence_feeds;
pub mod boot_protection;
pub mod code_signing;

// Re-export commonly used types
pub use etw_monitor::{ETWMonitor, ETWEvent, ETWAnalyzer};
pub use amsi_integration::{AMSIScanner, AMSIScanResult, AMSIResult};
pub use ml_threat_scoring::{MLThreatScorer, ThreatPrediction, FeatureVector};
pub use threat_intelligence_feeds::{ThreatIntelligence, IoC, IoCType};
pub use boot_protection::{BootProtection, BootProtectionStatus};
pub use code_signing::{CodeSigningVerifier, SignatureInfo};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize all EDR components
pub async fn initialize() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Initializing TamsilCMS Sentinel EDR v{}", VERSION);
    Ok(())
}
