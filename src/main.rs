//! TamsilCMS Sentinel Agent
//! Enterprise EDR agent for Windows, Linux, and macOS

use anyhow::{anyhow, Result};
use log::{error, info};

// Core modules
mod agent;
mod config;
mod state;
mod models;
mod policy;

// Track 1: Telemetry Collection
mod collectors;
mod fim_engine;
mod telemetry;
mod backend_client;

// Track 2: Detection
mod detection;
mod behavioral_analyzer;
mod behavioral_events;
mod behavioral_pipeline;
mod memory_analyzer;
mod memory_events;
mod memory_pipeline;
mod memory_scanner_edr;

// Track 3: Threat Intelligence
mod intel;

// Track 4: Response

// Additional modules
mod ingestion;

// Re-exports
use agent::EdrAgent;
use config::AgentConfig;

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    info!("TamsilCMS Sentinel Agent v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting EDR agent with all tracks enabled...");
    
    let config = AgentConfig::load().map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    info!("Configuration loaded successfully");

    info!("Creating agent instance...");
    let mut agent = EdrAgent::new(config).map_err(|e| anyhow!(e))?;

    info!("Starting agent loop...");
    if agent.config.run_once {
        let _ = agent.scan_once().map_err(|e| anyhow!(e))?;
    } else {
        agent.run_forever().map_err(|e| anyhow!(e))?;
    }
    
    info!("Agent shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_main_imports() {
        // Verify all modules compile
        assert!(true);
    }
}
