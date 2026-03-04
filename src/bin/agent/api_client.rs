//! API Client for Backend Communication

use reqwest::Client;
use std::time::Duration;

pub struct APIClient {
    client: Client,
    endpoint: String,
    api_key: String,
}

impl APIClient {
    pub fn new(endpoint: &str, api_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let normalized_endpoint = endpoint.trim().trim_end_matches('/').to_string();
        if normalized_endpoint.is_empty() {
            return Err("api endpoint cannot be empty".into());
        }

        let validation_url = format!("{}/", normalized_endpoint);
        let _ = reqwest::Url::parse(&validation_url)
            .map_err(|e| format!("invalid api endpoint '{}': {}", normalized_endpoint, e))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            endpoint: normalized_endpoint,
            api_key: api_key.trim().to_string(),
        })
    }

    pub async fn register_agent(
        &self,
        agent_info: &super::AgentInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/agents/register", self.endpoint);
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(agent_info)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Registration failed: {}", response.status()).into())
        }
    }

    pub async fn send_events(
        &self,
        events: &[serde_json::Value],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/events", self.endpoint);
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(events)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to send events: {}", response.status()).into())
        }
    }

    pub async fn get_commands(
        &self,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/commands", self.endpoint);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status().is_success() {
            let commands = response.json().await?;
            Ok(commands)
        } else {
            Ok(Vec::new())
        }
    }
}
