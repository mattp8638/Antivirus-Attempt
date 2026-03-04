// Alert Enrichment Module - Automatic ATT&CK and Threat Intel Tagging
// Applies enrichment to alerts based on detection rule and context

use crate::attack_mapping;
use crate::models::Alert;
use crate::threat_intel::{IndicatorType, ThreatIntelStore};
use serde_json::json;

/// Enrich an alert with ATT&CK mapping based on its rule
pub fn enrich_with_attack(alert: &mut Alert) {
    if let Some(mapping) = attack_mapping::get_mapping(&alert.rule) {
        alert.set_attack(mapping.tactic, mapping.technique);
        
        // Add ATT&CK IDs to details for structured querying
        let details = json!({
            "attack_tactic_id": mapping.tactic_id,
            "attack_technique_id": mapping.technique_id,
            "attack_description": mapping.description,
            "attack_tactic": mapping.tactic,
            "attack_technique": mapping.technique,
        });
        
        alert.set_details(details);
    }
}

/// Enrich alert with threat intel tags based on IOCs
pub fn enrich_with_threat_intel(
    alert: &mut Alert,
    intel_store: &ThreatIntelStore,
    context: &AlertContext,
) {
    // Check for IP-based IOCs
    if let Some(ref ip) = context.remote_ip {
        if let Some(indicator) = intel_store.check(IndicatorType::IpAddress, ip) {
            alert.add_tag(&format!("ti:ip:{}", indicator.severity));
            alert.add_tag(&format!("ti:source:{}", indicator.source));
            alert.add_tag(&format!("ti:confidence:{:.0}%", indicator.confidence * 100.0));
            
            // Add indicator-specific tags
            for tag in &indicator.tags {
                alert.add_tag(&format!("ti:tag:{}", tag));
            }
            
            // Update alert severity if threat intel indicates higher severity
            let current_weight = alert.severity_weight();
            let ti_weight = match indicator.severity.as_str() {
                "critical" => 10,
                "high" => 7,
                "medium" => 4,
                "low" => 1,
                _ => 0,
            };
            
            if ti_weight > current_weight {
                alert.severity = indicator.severity.clone();
            }
        }
    }
    
    // Check for domain-based IOCs
    if let Some(ref domain) = context.domain {
        if let Some(indicator) = intel_store.check(IndicatorType::Domain, domain) {
            alert.add_tag(&format!("ti:domain:{}", indicator.severity));
            alert.add_tag(&format!("ti:source:{}", indicator.source));
            
            for tag in &indicator.tags {
                alert.add_tag(&format!("ti:tag:{}", tag));
            }
        }
    }
    
    // Check for file hash IOCs
    if let Some(ref hash) = context.file_hash {
        if let Some(indicator) = intel_store.check(IndicatorType::FileHash, hash) {
            alert.add_tag(&format!("ti:file:{}", indicator.severity));
            alert.add_tag(&format!("ti:source:{}", indicator.source));
            alert.add_tag("ti:malware");
            
            for tag in &indicator.tags {
                alert.add_tag(&format!("ti:tag:{}", tag));
            }
            
            // File hash matches are always high priority
            if alert.severity_weight() < 7 {
                alert.severity = "high".to_string();
            }
        }
    }
    
    // Check for process name IOCs
    if let Some(ref process) = context.process_name {
        if let Some(indicator) = intel_store.check(IndicatorType::ProcessName, process) {
            alert.add_tag(&format!("ti:process:{}", indicator.severity));
            alert.add_tag(&format!("ti:source:{}", indicator.source));
            
            for tag in &indicator.tags {
                alert.add_tag(&format!("ti:tag:{}", tag));
            }
        }
    }
    
    // Check for command line IOCs (substring matching)
    if let Some(ref cmdline) = context.command_line {
        // Note: This requires a different approach since command lines are typically
        // matched via substrings rather than exact matches
        let cmdline_lower = cmdline.to_lowercase();
        for indicator in intel_store.get_by_type(IndicatorType::CommandLine) {
            if cmdline_lower.contains(&indicator.value.to_lowercase()) {
                alert.add_tag(&format!("ti:cmdline:{}", indicator.severity));
                alert.add_tag(&format!("ti:source:{}", indicator.source));
                
                for tag in &indicator.tags {
                    alert.add_tag(&format!("ti:tag:{}", tag));
                }
            }
        }
    }
    
    // Check for URL IOCs
    if let Some(ref url) = context.url {
        if let Some(indicator) = intel_store.check(IndicatorType::Url, url) {
            alert.add_tag(&format!("ti:url:{}", indicator.severity));
            alert.add_tag(&format!("ti:source:{}", indicator.source));
            
            for tag in &indicator.tags {
                alert.add_tag(&format!("ti:tag:{}", tag));
            }
        }
    }
}

/// Context information for alert enrichment
#[derive(Debug, Clone, Default)]
pub struct AlertContext {
    pub remote_ip: Option<String>,
    pub domain: Option<String>,
    pub file_hash: Option<String>,
    pub file_path: Option<String>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub url: Option<String>,
    pub port: Option<u16>,
}

impl AlertContext {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.remote_ip = Some(ip.into());
        self
    }
    
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
    
    pub fn with_file_hash(mut self, hash: impl Into<String>) -> Self {
        self.file_hash = Some(hash.into());
        self
    }
    
    pub fn with_file_path(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }
    
    pub fn with_process(mut self, process: impl Into<String>) -> Self {
        self.process_name = Some(process.into());
        self
    }
    
    pub fn with_command_line(mut self, cmdline: impl Into<String>) -> Self {
        self.command_line = Some(cmdline.into());
        self
    }
    
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
    
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

/// Full enrichment pipeline: ATT&CK + Threat Intel
pub fn enrich_alert(
    alert: &mut Alert,
    intel_store: Option<&ThreatIntelStore>,
    context: Option<&AlertContext>,
) {
    // Always apply ATT&CK mapping
    enrich_with_attack(alert);
    
    // Apply threat intel if available
    if let (Some(store), Some(ctx)) = (intel_store, context) {
        enrich_with_threat_intel(alert, store, ctx);
    }
}

/// Batch enrichment for multiple alerts
pub fn enrich_alerts(
    alerts: &mut [Alert],
    intel_store: Option<&ThreatIntelStore>,
    contexts: Option<&[AlertContext]>,
) {
    if let Some(contexts) = contexts {
        for (alert, context) in alerts.iter_mut().zip(contexts.iter()) {
            enrich_alert(alert, intel_store, Some(context));
        }
    } else {
        for alert in alerts.iter_mut() {
            enrich_alert(alert, intel_store, None);
        }
    }
}

/// Generate enrichment summary statistics
#[derive(Debug, Clone)]
pub struct EnrichmentStats {
    pub alerts_processed: usize,
    pub attack_mappings_applied: usize,
    pub threat_intel_hits: usize,
    pub severity_escalations: usize,
}

impl EnrichmentStats {
    pub fn new() -> Self {
        Self {
            alerts_processed: 0,
            attack_mappings_applied: 0,
            threat_intel_hits: 0,
            severity_escalations: 0,
        }
    }
}

impl Default for EnrichmentStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Enrich alerts with statistics tracking
pub fn enrich_alerts_with_stats(
    alerts: &mut [Alert],
    intel_store: Option<&ThreatIntelStore>,
    contexts: Option<&[AlertContext]>,
) -> EnrichmentStats {
    let mut stats = EnrichmentStats::new();
    
    if let Some(contexts) = contexts {
        for (alert, context) in alerts.iter_mut().zip(contexts.iter()) {
            let initial_severity = alert.severity_weight();
            let initial_tags = alert.intel_tags.len();
            
            enrich_alert(alert, intel_store, Some(context));
            
            stats.alerts_processed += 1;
            
            if alert.attack_tactic.is_some() {
                stats.attack_mappings_applied += 1;
            }
            
            if alert.intel_tags.len() > initial_tags {
                stats.threat_intel_hits += 1;
            }
            
            if alert.severity_weight() > initial_severity {
                stats.severity_escalations += 1;
            }
        }
    } else {
        for alert in alerts.iter_mut() {
            let initial_severity = alert.severity_weight();
            
            enrich_alert(alert, intel_store, None);
            
            stats.alerts_processed += 1;
            
            if alert.attack_tactic.is_some() {
                stats.attack_mappings_applied += 1;
            }
            
            if alert.severity_weight() > initial_severity {
                stats.severity_escalations += 1;
            }
        }
    }
    
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Alert;
    use crate::threat_intel::{ThreatIndicator, ThreatIntelStore};

    #[test]
    fn test_attack_enrichment() {
        let mut alert = Alert::new("blocked_process_name", "medium", "Test alert".into());
        
        enrich_with_attack(&mut alert);
        
        assert_eq!(alert.attack_tactic, Some("Execution".to_string()));
        assert_eq!(alert.attack_technique, Some("Command and Scripting Interpreter".to_string()));
        assert!(alert.details.is_some());
    }

    #[test]
    fn test_threat_intel_enrichment_ip() {
        let mut store = ThreatIntelStore::new();
        let mut indicator = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.2.3.4",
            "test_feed",
            0.95,
            "critical",
            3600,
        );
        indicator.add_tag("botnet");
        indicator.add_tag("malware");
        store.add_indicator(indicator);
        
        let mut alert = Alert::new("blocked_remote_ip", "medium", "Test connection".into());
        let context = AlertContext::new().with_ip("1.2.3.4");
        
        enrich_with_threat_intel(&mut alert, &store, &context);
        
        assert!(alert.intel_tags.iter().any(|t| t.contains("ti:ip:critical")));
        assert!(alert.intel_tags.iter().any(|t| t.contains("ti:tag:botnet")));
        assert_eq!(alert.severity, "critical"); // Escalated from medium
    }

    #[test]
    fn test_threat_intel_enrichment_file_hash() {
        let mut store = ThreatIntelStore::new();
        let mut indicator = ThreatIndicator::new(
            IndicatorType::FileHash,
            "abc123",
            "virustotal",
            0.99,
            "high",
            7200,
        );
        indicator.add_tag("ransomware");
        store.add_indicator(indicator);
        
        let mut alert = Alert::new("new_file_detected", "low", "New file".into());
        let context = AlertContext::new().with_file_hash("abc123");
        
        enrich_with_threat_intel(&mut alert, &store, &context);
        
        assert!(alert.intel_tags.iter().any(|t| t.contains("ti:file:high")));
        assert!(alert.intel_tags.iter().any(|t| t.contains("ti:malware")));
        assert!(alert.intel_tags.iter().any(|t| t.contains("ti:tag:ransomware")));
        assert_eq!(alert.severity, "high"); // Escalated from low
    }

    #[test]
    fn test_full_enrichment_pipeline() {
        let mut store = ThreatIntelStore::new();
        let indicator = ThreatIndicator::new(
            IndicatorType::Domain,
            "evil.com",
            "test_feed",
            0.85,
            "medium",
            3600,
        );
        store.add_indicator(indicator);
        
        let mut alert = Alert::new("blocked_remote_ip", "low", "Suspicious connection".into());
        let context = AlertContext::new().with_domain("evil.com");
        
        enrich_alert(&mut alert, Some(&store), Some(&context));
        
        // Should have ATT&CK mapping
        assert!(alert.attack_tactic.is_some());
        assert!(alert.attack_technique.is_some());
        
        // Should have threat intel tags
        assert!(!alert.intel_tags.is_empty());
    }

    #[test]
    fn test_batch_enrichment() {
        let mut alerts = vec![
            Alert::new("blocked_process_name", "medium", "Alert 1".into()),
            Alert::new("file_modified", "low", "Alert 2".into()),
        ];
        
        enrich_alerts(&mut alerts, None, None);
        
        assert!(alerts[0].attack_tactic.is_some());
        assert!(alerts[1].attack_tactic.is_some());
    }

    #[test]
    fn test_enrichment_stats() {
        let mut store = ThreatIntelStore::new();
        let indicator = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.1.1.1",
            "test",
            0.9,
            "critical",
            3600,
        );
        store.add_indicator(indicator);
        
        let mut alerts = vec![
            Alert::new("blocked_remote_ip", "low", "Alert 1".into()),
            Alert::new("file_modified", "medium", "Alert 2".into()),
        ];
        
        let contexts = vec![
            AlertContext::new().with_ip("1.1.1.1"),
            AlertContext::new(),
        ];
        
        let stats = enrich_alerts_with_stats(&mut alerts, Some(&store), Some(&contexts));
        
        assert_eq!(stats.alerts_processed, 2);
        assert_eq!(stats.attack_mappings_applied, 2);
        assert_eq!(stats.threat_intel_hits, 1);
        assert_eq!(stats.severity_escalations, 1);
    }
}
