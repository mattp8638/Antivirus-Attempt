#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{anyhow, Result};

#[path = "agent.rs"]
mod agent_bin;
#[path = "endpoint_ui.rs"]
mod endpoint_ui_bin;

#[tokio::main]
async fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "both".to_string())
        .to_lowercase();

    match mode.as_str() {
        "agent" => {
            agent_bin::agent_entry()
                .await
                .map_err(|e| anyhow!("agent mode failed: {e}"))?;
        }
        "ui" => {
            endpoint_ui_bin::endpoint_ui_entry()
                .map_err(|e| anyhow!("ui mode failed: {e}"))?;
        }
        "both" => {
            let _agent_thread = std::thread::spawn(|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow!("failed to create runtime: {e}"))?;

                runtime
                    .block_on(agent_bin::agent_entry())
                    .map_err(|e| anyhow!("agent task failed: {e}"))
            });

            let ui_result = endpoint_ui_bin::endpoint_ui_entry();

            ui_result.map_err(|e| anyhow!("ui mode failed: {e}"))?;
        }
        _ => {
            return Err(anyhow!(
                "invalid mode '{}'. Use: tamsilcms-suite [agent|ui|both]",
                mode
            ));
        }
    }

    Ok(())
}
