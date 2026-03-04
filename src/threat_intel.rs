use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Threat intel indicator types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    FileHash,
    Url,
    Email,
    ProcessName,
    CommandLine,
}

/// Threat intel feed source metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSource {
    pub source_id: String,
    pub source_name: String,
    pub description: Option<String>,
    pub last_updated: u64,
}

/// Threat intel indicator with enrichment metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub source: String,
    pub confidence: f32, // 0.0 to 1.0
    pub severity: String, // low, medium, high, critical
    pub tags: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub expires_at: u64,
    pub metadata: HashMap<String, String>,
}

impl ThreatIndicator {
    pub fn new(
        indicator_type: IndicatorType,
        value: impl Into<String>,
        source: impl Into<String>,
        confidence: f32,
        severity: impl Into<String>,
        ttl_seconds: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let value = value.into();
        let indicator_id = format!("{:?}:{}", indicator_type, value);

        Self {
            indicator_id,
            indicator_type,
            value,
            source: source.into(),
            confidence: confidence.clamp(0.0, 1.0),
            severity: severity.into(),
            tags: Vec::new(),
            first_seen: now,
            last_seen: now,
            expires_at: now + ttl_seconds,
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self, current_ts: u64) -> bool {
        current_ts >= self.expires_at
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    pub fn refresh_expiry(&mut self, ttl_seconds: u64, current_ts: u64) {
        self.last_seen = current_ts;
        self.expires_at = current_ts + ttl_seconds;
    }
}

/// Threat intel feed store with de-duplication and TTL management
pub struct ThreatIntelStore {
    /// Indicators indexed by indicator_id
    indicators: HashMap<String, ThreatIndicator>,
    /// Fast lookup by type and value: (type, value) -> indicator_id
    lookup: HashMap<(IndicatorType, String), String>,
    /// Feed sources
    sources: HashMap<String, FeedSource>,
    /// Last cleanup timestamp
    last_cleanup: u64,
}

impl Default for ThreatIntelStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelStore {
    pub fn new() -> Self {
        Self {
            indicators: HashMap::new(),
            lookup: HashMap::new(),
            sources: HashMap::new(),
            last_cleanup: 0,
        }
    }

    /// Register or update a feed source
    pub fn register_source(
        &mut self,
        source_id: impl Into<String>,
        source_name: impl Into<String>,
        description: Option<String>,
    ) {
        let source_id = source_id.into();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.sources.insert(
            source_id.clone(),
            FeedSource {
                source_id,
                source_name: source_name.into(),
                description,
                last_updated: now,
            },
        );
    }

    /// Add or update a threat indicator with de-duplication
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) -> bool {
        let key = (indicator.indicator_type, indicator.value.clone());

        if let Some(existing_id) = self.lookup.get(&key) {
            // De-duplicate: update existing indicator
            if let Some(existing) = self.indicators.get_mut(existing_id) {
                existing.last_seen = indicator.last_seen;
                existing.expires_at = indicator.expires_at;

                // Merge tags
                for tag in &indicator.tags {
                    existing.add_tag(tag.clone());
                }

                // Merge metadata
                for (k, v) in &indicator.metadata {
                    existing.add_metadata(k.clone(), v.clone());
                }

                // Update confidence if higher
                if indicator.confidence > existing.confidence {
                    existing.confidence = indicator.confidence;
                }

                return false; // Existing indicator updated
            }
        }

        // New indicator
        let indicator_id = indicator.indicator_id.clone();
        self.lookup.insert(key, indicator_id.clone());
        self.indicators.insert(indicator_id, indicator);
        true // New indicator added
    }

    /// Bulk add indicators with de-duplication tracking
    pub fn add_indicators(&mut self, indicators: Vec<ThreatIndicator>) -> (usize, usize) {
        let mut added = 0;
        let mut updated = 0;

        for indicator in indicators {
            if self.add_indicator(indicator) {
                added += 1;
            } else {
                updated += 1;
            }
        }

        (added, updated)
    }

    /// Check if a value matches any indicator of the given type
    pub fn check(&self, indicator_type: IndicatorType, value: &str) -> Option<&ThreatIndicator> {
        let key = (indicator_type, value.to_string());
        self.lookup
            .get(&key)
            .and_then(|id| self.indicators.get(id))
    }

    /// Get all indicators of a specific type
    pub fn get_by_type(&self, indicator_type: IndicatorType) -> Vec<&ThreatIndicator> {
        self.indicators
            .values()
            .filter(|ind| ind.indicator_type == indicator_type)
            .collect()
    }

    /// Get all active (non-expired) indicators
    pub fn get_active_indicators(&self, current_ts: u64) -> Vec<&ThreatIndicator> {
        self.indicators
            .values()
            .filter(|ind| !ind.is_expired(current_ts))
            .collect()
    }

    /// Cleanup expired indicators (TTL enforcement)
    pub fn cleanup_expired(&mut self, current_ts: u64) -> usize {
        let expired_ids: Vec<String> = self
            .indicators
            .iter()
            .filter(|(_, ind)| ind.is_expired(current_ts))
            .map(|(id, _)| id.clone())
            .collect();

        let removed = expired_ids.len();

        for id in expired_ids {
            if let Some(indicator) = self.indicators.remove(&id) {
                let key = (indicator.indicator_type, indicator.value.clone());
                self.lookup.remove(&key);
            }
        }

        self.last_cleanup = current_ts;
        removed
    }

    /// Auto-cleanup expired indicators if interval has passed
    pub fn auto_cleanup(&mut self, cleanup_interval_seconds: u64) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(self.last_cleanup) >= cleanup_interval_seconds {
            self.cleanup_expired(now)
        } else {
            0
        }
    }

    /// Get statistics about the store
    pub fn stats(&self, current_ts: u64) -> ThreatIntelStats {
        let active = self.get_active_indicators(current_ts).len();
        let expired = self.indicators.len().saturating_sub(active);

        let mut by_type: HashMap<IndicatorType, usize> = HashMap::new();
        for indicator in self.indicators.values() {
            *by_type.entry(indicator.indicator_type).or_default() += 1;
        }

        let mut by_source: HashMap<String, usize> = HashMap::new();
        for indicator in self.indicators.values() {
            *by_source.entry(indicator.source.clone()).or_default() += 1;
        }

        ThreatIntelStats {
            total_indicators: self.indicators.len(),
            active_indicators: active,
            expired_indicators: expired,
            by_type,
            by_source,
            source_count: self.sources.len(),
        }
    }

    /// Export indicators for persistence (e.g., to SQLite or JSON)
    pub fn export_indicators(&self) -> Vec<ThreatIndicator> {
        self.indicators.values().cloned().collect()
    }

    /// Import indicators from persistence
    pub fn import_indicators(&mut self, indicators: Vec<ThreatIndicator>) -> (usize, usize) {
        self.add_indicators(indicators)
    }
}

/// Statistics about the threat intel store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStats {
    pub total_indicators: usize,
    pub active_indicators: usize,
    pub expired_indicators: usize,
    pub by_type: HashMap<IndicatorType, usize>,
    pub by_source: HashMap<String, usize>,
    pub source_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_indicator_with_ttl() {
        let indicator = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.2.3.4",
            "test_source",
            0.95,
            "high",
            3600,
        );

        assert_eq!(indicator.value, "1.2.3.4");
        assert_eq!(indicator.confidence, 0.95);
        assert!(indicator.expires_at > indicator.first_seen);
    }

    #[test]
    fn detects_expired_indicators() {
        let mut indicator = ThreatIndicator::new(
            IndicatorType::Domain,
            "evil.com",
            "source1",
            0.8,
            "medium",
            100,
        );

        assert!(!indicator.is_expired(indicator.first_seen + 50));
        assert!(indicator.is_expired(indicator.first_seen + 200));
    }

    #[test]
    fn deduplicates_indicators() {
        let mut store = ThreatIntelStore::new();

        let ind1 = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.2.3.4",
            "source1",
            0.7,
            "medium",
            3600,
        );

        let mut ind2 = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.2.3.4",
            "source2",
            0.9,
            "high",
            3600,
        );
        ind2.add_tag("malware");

        assert!(store.add_indicator(ind1));
        assert!(!store.add_indicator(ind2)); // Deduplicated

        let result = store.check(IndicatorType::IpAddress, "1.2.3.4").unwrap();
        assert_eq!(result.confidence, 0.9); // Updated to higher confidence
        assert!(result.tags.contains(&"malware".to_string()));
    }

    #[test]
    fn checks_indicators() {
        let mut store = ThreatIntelStore::new();

        let indicator = ThreatIndicator::new(
            IndicatorType::FileHash,
            "abc123",
            "source1",
            0.95,
            "critical",
            3600,
        );

        store.add_indicator(indicator);

        assert!(store
            .check(IndicatorType::FileHash, "abc123")
            .is_some());
        assert!(store.check(IndicatorType::FileHash, "def456").is_none());
        assert!(store.check(IndicatorType::IpAddress, "abc123").is_none());
    }

    #[test]
    fn cleans_up_expired_indicators() {
        let mut store = ThreatIntelStore::new();

        let mut ind1 = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.1.1.1",
            "source1",
            0.8,
            "high",
            100,
        );
        ind1.first_seen = 1000;
        ind1.expires_at = 1100;

        let mut ind2 = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "2.2.2.2",
            "source1",
            0.9,
            "high",
            5000,
        );
        ind2.first_seen = 1000;
        ind2.expires_at = 6000;

        store.add_indicator(ind1);
        store.add_indicator(ind2);

        assert_eq!(store.indicators.len(), 2);

        let removed = store.cleanup_expired(1200);
        assert_eq!(removed, 1);
        assert_eq!(store.indicators.len(), 1);
        assert!(store.check(IndicatorType::IpAddress, "2.2.2.2").is_some());
        assert!(store.check(IndicatorType::IpAddress, "1.1.1.1").is_none());
    }

    #[test]
    fn tracks_statistics() {
        let mut store = ThreatIntelStore::new();

        store.register_source("src1", "Source One", Some("Test source".into()));

        let ind1 = ThreatIndicator::new(
            IndicatorType::IpAddress,
            "1.1.1.1",
            "src1",
            0.8,
            "high",
            3600,
        );
        let ind2 = ThreatIndicator::new(
            IndicatorType::Domain,
            "evil.com",
            "src1",
            0.9,
            "high",
            3600,
        );

        store.add_indicator(ind1);
        store.add_indicator(ind2);

        let stats = store.stats(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs());

        assert_eq!(stats.total_indicators, 2);
        assert_eq!(stats.active_indicators, 2);
        assert_eq!(stats.source_count, 1);
        assert_eq!(*stats.by_type.get(&IndicatorType::IpAddress).unwrap(), 1);
        assert_eq!(*stats.by_type.get(&IndicatorType::Domain).unwrap(), 1);
    }

    #[test]
    fn exports_and_imports_indicators() {
        let mut store1 = ThreatIntelStore::new();

        let ind = ThreatIndicator::new(
            IndicatorType::Url,
            "http://evil.com/malware",
            "src1",
            0.95,
            "critical",
            3600,
        );

        store1.add_indicator(ind);

        let exported = store1.export_indicators();
        assert_eq!(exported.len(), 1);

        let mut store2 = ThreatIntelStore::new();
        let (added, updated) = store2.import_indicators(exported);

        assert_eq!(added, 1);
        assert_eq!(updated, 0);
        assert!(store2
            .check(IndicatorType::Url, "http://evil.com/malware")
            .is_some());
    }
}
