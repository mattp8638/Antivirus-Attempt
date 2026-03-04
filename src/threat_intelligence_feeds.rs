//! Threat Intelligence Feed Integration
//!
//! Integrates with multiple threat intelligence sources:
//! - MISP (Malware Information Sharing Platform)
//! - AlienVault OTX
//! - VirusTotal
//! - AbuseIPDB
//! - Custom threat feeds
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::Ipv4Addr;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Indicator of Compromise (IoC) types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IoCType {
    FileHash(String),      // SHA256/MD5
    IPAddress(String),
    Domain(String),
    URL(String),
    Email(String),
    Mutex(String),
    RegistryKey(String),
    FilePath(String),
}

/// Threat intel source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSource {
    MISP,
    AlienVault,
    VirusTotal,
    AbuseIPDB,
    CustomFeed(String),
}

/// IoC record from threat feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: IoCType,
    pub value: String,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub source: ThreatSource,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub mitre_attack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat intelligence cache
pub struct ThreatIntelCache {
    iocs: Arc<RwLock<HashMap<IoCType, IoC>>>,
    malicious_ips: Arc<RwLock<HashSet<String>>>,
    malicious_domains: Arc<RwLock<HashSet<String>>>,
    malicious_hashes: Arc<RwLock<HashSet<String>>>,
    last_update: Arc<RwLock<SystemTime>>,
}

impl ThreatIntelCache {
    pub fn new() -> Self {
        Self {
            iocs: Arc::new(RwLock::new(HashMap::new())),
            malicious_ips: Arc::new(RwLock::new(HashSet::new())),
            malicious_domains: Arc::new(RwLock::new(HashSet::new())),
            malicious_hashes: Arc::new(RwLock::new(HashSet::new())),
            last_update: Arc::new(RwLock::new(SystemTime::now())),
        }
    }

    /// Add IoC to cache
    pub fn add_ioc(&self, ioc: IoC) {
        let ioc_type = ioc.ioc_type.clone();
        let value = ioc.value.clone();

        // Add to type-specific cache for fast lookups
        match &ioc.ioc_type {
            IoCType::IPAddress(_) => {
                if let Ok(mut ips) = self.malicious_ips.write() {
                    ips.insert(value.clone());
                }
            }
            IoCType::Domain(_) => {
                if let Ok(mut domains) = self.malicious_domains.write() {
                    domains.insert(value.clone());
                }
            }
            IoCType::FileHash(_) => {
                if let Ok(mut hashes) = self.malicious_hashes.write() {
                    hashes.insert(value.clone());
                }
            }
            _ => {}
        }

        // Add to main cache
        if let Ok(mut iocs) = self.iocs.write() {
            iocs.insert(ioc_type, ioc);
        }
    }

    /// Check if IP is malicious
    pub fn is_malicious_ip(&self, ip: &str) -> Option<IoC> {
        if let Ok(ips) = self.malicious_ips.read() {
            if ips.contains(ip) {
                return self.get_ioc(&IoCType::IPAddress(ip.to_string()));
            }
        }
        None
    }

    /// Check if domain is malicious
    pub fn is_malicious_domain(&self, domain: &str) -> Option<IoC> {
        if let Ok(domains) = self.malicious_domains.read() {
            if domains.contains(domain) {
                return self.get_ioc(&IoCType::Domain(domain.to_string()));
            }
        }
        None
    }

    /// Check if file hash is malicious
    pub fn is_malicious_hash(&self, hash: &str) -> Option<IoC> {
        if let Ok(hashes) = self.malicious_hashes.read() {
            if hashes.contains(hash) {
                return self.get_ioc(&IoCType::FileHash(hash.to_string()));
            }
        }
        None
    }

    fn get_ioc(&self, ioc_type: &IoCType) -> Option<IoC> {
        if let Ok(iocs) = self.iocs.read() {
            iocs.get(ioc_type).cloned()
        } else {
            None
        }
    }
}

/// Threat intelligence manager
pub struct ThreatIntelligence {
    cache: ThreatIntelCache,
    update_interval: Duration,
}

impl ThreatIntelligence {
    pub fn new() -> Self {
        let mut intel = Self {
            cache: ThreatIntelCache::new(),
            update_interval: Duration::from_secs(3600), // 1 hour
        };

        // Load initial threat data
        intel.load_initial_threats();
        intel
    }

    fn load_initial_threats(&mut self) {
        // Load known malicious IPs
        let malicious_ips = vec![
            "185.220.101.1",
            "45.142.214.1",
            "104.244.72.1",
        ];

        for ip in &malicious_ips {
            self.cache.add_ioc(IoC {
            ioc_type: IoCType::IPAddress((*ip).to_string()),
            value: (*ip).to_string(),
                threat_type: "C2 Server".to_string(),
                severity: ThreatSeverity::Critical,
                first_seen: SystemTime::now(),
                last_seen: SystemTime::now(),
                source: ThreatSource::CustomFeed("Initial".to_string()),
                tags: vec!["c2".to_string(), "botnet".to_string()],
                description: Some("Known C2 server".to_string()),
                mitre_attack: vec!["T1071".to_string()],
            });
        }

        tracing::info!("Loaded {} initial threat indicators", malicious_ips.len());
    }

    /// Start threat feed updates
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting threat intelligence feeds");
        
        let intel = self.clone_ref();
        tokio::spawn(async move {
            intel.update_loop().await;
        });
        
        Ok(())
    }

    async fn update_loop(&self) {
        let mut interval = tokio::time::interval(self.update_interval);
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.update_feeds().await {
                tracing::error!("Threat feed update failed: {}", e);
            }
        }
    }

    async fn update_feeds(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Updating threat intelligence feeds");

        let mut added_hashes = 0usize;
        let mut added_ips = 0usize;

        match self.fetch_malwarebazaar_hashes().await {
            Ok(count) => {
                added_hashes += count;
            }
            Err(err) => {
                tracing::warn!("MalwareBazaar feed update failed: {}", err);
            }
        }

        match self.fetch_abuseipdb_blacklist().await {
            Ok(count) => {
                added_ips += count;
            }
            Err(err) => {
                tracing::warn!("AbuseIPDB feed update failed: {}", err);
            }
        }

        if let Ok(mut ts) = self.cache.last_update.write() {
            *ts = SystemTime::now();
        }

        tracing::info!(
            "Threat feed update complete: added_hashes={} added_ips={}",
            added_hashes,
            added_ips
        );
        
        Ok(())
    }

    async fn fetch_malwarebazaar_hashes(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let url = "https://bazaar.abuse.ch/export/csv/recent/";
        let response = reqwest::get(url).await?;
        if !response.status().is_success() {
            return Err(format!("MalwareBazaar returned status {}", response.status()).into());
        }

        let body = response.text().await?;
        let mut added = 0usize;
        let max_ingest = 10000usize;

        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let hash = trimmed
                .split(',')
                .find_map(|column| {
                    let candidate = column.trim_matches('"').trim();
                    if candidate.len() == 64
                        && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
                    {
                        Some(candidate.to_lowercase())
                    } else {
                        None
                    }
                });

            if let Some(hash_value) = hash {
                self.cache.add_ioc(IoC {
                    ioc_type: IoCType::FileHash(hash_value.clone()),
                    value: hash_value,
                    threat_type: "Malware Sample".to_string(),
                    severity: ThreatSeverity::High,
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    source: ThreatSource::CustomFeed("MalwareBazaar".to_string()),
                    tags: vec!["malware".to_string(), "hash".to_string()],
                    description: Some("Imported from MalwareBazaar recent feed".to_string()),
                    mitre_attack: vec!["T1588.001".to_string()],
                });
                added += 1;

                if added >= max_ingest {
                    break;
                }
            }
        }

        Ok(added)
    }

    async fn fetch_abuseipdb_blacklist(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let api_key = match std::env::var("ABUSEIPDB_API_KEY") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => return Ok(0),
        };

        let client = reqwest::Client::new();
        let response = client
            .get("https://api.abuseipdb.com/api/v2/blacklist")
            .header("Key", api_key)
            .header("Accept", "application/json")
            .query(&[("confidenceMinimum", "90"), ("limit", "1000")])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("AbuseIPDB returned status {}", response.status()).into());
        }

        let payload: Value = response.json().await?;
        let mut added = 0usize;

        if let Some(entries) = payload
            .get("data")
            .and_then(|value| value.as_array())
        {
            for entry in entries {
                let ip = match entry.get("ipAddress").and_then(|value| value.as_str()) {
                    Some(value) if !value.trim().is_empty() => value.to_string(),
                    _ => continue,
                };

                if !Self::is_public_ipv4(&ip) {
                    continue;
                }

                self.cache.add_ioc(IoC {
                    ioc_type: IoCType::IPAddress(ip.clone()),
                    value: ip,
                    threat_type: "Abusive IP".to_string(),
                    severity: ThreatSeverity::High,
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    source: ThreatSource::AbuseIPDB,
                    tags: vec!["abuseipdb".to_string(), "c2".to_string()],
                    description: Some("Imported from AbuseIPDB blacklist".to_string()),
                    mitre_attack: vec!["T1071".to_string()],
                });
                added += 1;
            }
        }

        Ok(added)
    }

    fn is_public_ipv4(ip: &str) -> bool {
        let parsed = match ip.parse::<Ipv4Addr>() {
            Ok(value) => value,
            Err(_) => return false,
        };

        if parsed.is_private() || parsed.is_loopback() || parsed.is_link_local() || parsed.is_multicast() {
            return false;
        }

        let octets = parsed.octets();
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return false;
        }

        if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
            return false;
        }

        true
    }

    /// Check if file hash is known malware
    pub fn check_file_hash(&self, hash: &str) -> Option<IoC> {
        self.cache.is_malicious_hash(hash)
    }

    /// Check if IP is known malicious
    pub fn check_ip(&self, ip: &str) -> Option<IoC> {
        self.cache.is_malicious_ip(ip)
    }

    /// Check if domain is known malicious
    pub fn check_domain(&self, domain: &str) -> Option<IoC> {
        self.cache.is_malicious_domain(domain)
    }

    fn clone_ref(&self) -> Self {
        Self {
            cache: ThreatIntelCache {
                iocs: Arc::clone(&self.cache.iocs),
                malicious_ips: Arc::clone(&self.cache.malicious_ips),
                malicious_domains: Arc::clone(&self.cache.malicious_domains),
                malicious_hashes: Arc::clone(&self.cache.malicious_hashes),
                last_update: Arc::clone(&self.cache.last_update),
            },
            update_interval: self.update_interval,
        }
    }
}
