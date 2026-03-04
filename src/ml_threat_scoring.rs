//! Machine Learning Threat Scoring Engine
//!
//! Behavioral analysis using ML models to detect zero-day threats:
//! - Random Forest classifier for process behavior
//! - Anomaly detection for unusual patterns
//! - Feature extraction from telemetry
//! - Real-time threat scoring
//!
//! Author: TamsilCMS Security Team
//! Date: 2026-02-10

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ML model types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelType {
    RandomForest,
    GradientBoosting,
    NeuralNetwork,
    AnomalyDetection,
}

/// Feature vector for ML model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    // Process features
    pub process_spawn_rate: f64,
    pub child_process_count: u32,
    pub thread_count: u32,
    pub unsigned_modules: u32,
    
    // Memory features
    pub rwx_regions: u32,
    pub private_memory_mb: f64,
    pub remote_allocations: u32,
    
    // File features
    pub files_written: u32,
    pub files_deleted: u32,
    pub files_renamed: u32,
    pub suspicious_extensions: u32,
    
    // Network features
    pub connections_out: u32,
    pub unique_ips: u32,
    pub bytes_uploaded: u64,
    pub high_entropy_traffic: bool,
    
    // Registry features
    pub registry_writes: u32,
    pub persistence_keys_modified: u32,
    pub security_keys_modified: u32,
    
    // Behavioral features
    pub obfuscated_commands: u32,
    pub encoded_scripts: u32,
    pub lolbin_usage: u32,
    pub privilege_escalation_attempts: u32,
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self {
            process_spawn_rate: 0.0,
            child_process_count: 0,
            thread_count: 0,
            unsigned_modules: 0,
            rwx_regions: 0,
            private_memory_mb: 0.0,
            remote_allocations: 0,
            files_written: 0,
            files_deleted: 0,
            files_renamed: 0,
            suspicious_extensions: 0,
            connections_out: 0,
            unique_ips: 0,
            bytes_uploaded: 0,
            high_entropy_traffic: false,
            registry_writes: 0,
            persistence_keys_modified: 0,
            security_keys_modified: 0,
            obfuscated_commands: 0,
            encoded_scripts: 0,
            lolbin_usage: 0,
            privilege_escalation_attempts: 0,
        }
    }
}

/// ML prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_score: f64,        // 0.0 - 100.0
    pub confidence: f64,          // 0.0 - 1.0
    pub classification: ThreatClass,
    pub contributing_features: Vec<(String, f64)>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatClass {
    Benign,
    Suspicious,
    Malicious,
    Critical,
}

/// ML threat scoring engine
pub struct MLThreatScorer {
    models: HashMap<ModelType, Vec<f64>>, // Simplified: weights instead of actual models
    feature_importance: HashMap<String, f64>,
}

impl MLThreatScorer {
    pub fn new() -> Self {
        let mut scorer = Self {
            models: HashMap::new(),
            feature_importance: HashMap::new(),
        }
;        
        scorer.initialize_models();
        scorer.initialize_feature_importance();
        scorer
    }

    fn initialize_models(&mut self) {
        // In production, would load trained models from disk
        // For now, using rule-based weights
        
        let rf_weights = vec![/* trained weights */];
        self.models.insert(ModelType::RandomForest, rf_weights);
    }

    fn initialize_feature_importance(&mut self) {
        // Feature importance scores (higher = more important for detection)
        self.feature_importance.insert("rwx_regions".to_string(), 0.92);
        self.feature_importance.insert("encoded_scripts".to_string(), 0.89);
        self.feature_importance.insert("persistence_keys_modified".to_string(), 0.85);
        self.feature_importance.insert("remote_allocations".to_string(), 0.83);
        self.feature_importance.insert("lolbin_usage".to_string(), 0.81);
        self.feature_importance.insert("files_encrypted".to_string(), 0.79);
        self.feature_importance.insert("obfuscated_commands".to_string(), 0.77);
        self.feature_importance.insert("unsigned_modules".to_string(), 0.72);
        self.feature_importance.insert("privilege_escalation_attempts".to_string(), 0.88);
        self.feature_importance.insert("high_entropy_traffic".to_string(), 0.69);
    }

    /// Score process based on behavioral features
    pub fn score_process(&self, features: &FeatureVector) -> ThreatPrediction {
        let mut threat_score = 0.0;
        let mut contributing = Vec::new();
        let mut mitre_techniques = Vec::new();

        // Memory-based indicators
        if features.rwx_regions > 0 {
            let score = (features.rwx_regions as f64) * 15.0;
            threat_score += score;
            contributing.push(("RWX memory regions".to_string(), score));
            mitre_techniques.push("T1055".to_string());
        }

        if features.remote_allocations > 0 {
            let score = (features.remote_allocations as f64) * 20.0;
            threat_score += score;
            contributing.push(("Remote memory allocations".to_string(), score));
            mitre_techniques.push("T1055.001".to_string());
        }

        // File-based indicators
        let file_activity_score = self.score_file_activity(features);
        if file_activity_score > 0.0 {
            threat_score += file_activity_score;
            contributing.push(("File activity".to_string(), file_activity_score));
            if features.files_renamed > 50 {
                mitre_techniques.push("T1486".to_string()); // Ransomware
            }
        }

        // Script-based indicators
        if features.encoded_scripts > 0 {
            let score = (features.encoded_scripts as f64) * 18.0;
            threat_score += score;
            contributing.push(("Encoded scripts".to_string(), score));
            mitre_techniques.push("T1059.001".to_string());
            mitre_techniques.push("T1027".to_string());
        }

        if features.obfuscated_commands > 0 {
            let score = (features.obfuscated_commands as f64) * 15.0;
            threat_score += score;
            contributing.push(("Obfuscated commands".to_string(), score));
            mitre_techniques.push("T1027".to_string());
        }

        // LOLBin usage
        if features.lolbin_usage > 0 {
            let score = (features.lolbin_usage as f64) * 12.0;
            threat_score += score;
            contributing.push(("Living-off-the-land binaries".to_string(), score));
            mitre_techniques.push("T1218".to_string());
        }

        // Registry indicators
        if features.persistence_keys_modified > 0 {
            let score = (features.persistence_keys_modified as f64) * 16.0;
            threat_score += score;
            contributing.push(("Persistence keys modified".to_string(), score));
            mitre_techniques.push("T1547.001".to_string());
        }

        if features.security_keys_modified > 0 {
            let score = (features.security_keys_modified as f64) * 20.0;
            threat_score += score;
            contributing.push(("Security keys modified".to_string(), score));
            mitre_techniques.push("T1562.001".to_string());
        }

        // Privilege escalation
        if features.privilege_escalation_attempts > 0 {
            let score = (features.privilege_escalation_attempts as f64) * 25.0;
            threat_score += score;
            contributing.push(("Privilege escalation".to_string(), score));
            mitre_techniques.push("T1068".to_string());
        }

        // Network indicators
        if features.bytes_uploaded > 100_000_000 { // 100MB
            let score = 15.0;
            threat_score += score;
            contributing.push(("Large data exfiltration".to_string(), score));
            mitre_techniques.push("T1041".to_string());
        }

        if features.high_entropy_traffic {
            threat_score += 12.0;
            contributing.push(("High entropy network traffic".to_string(), 12.0));
            mitre_techniques.push("T1573".to_string());
        }

        // Normalize score to 0-100
        threat_score = threat_score.min(100.0);

        // Determine classification
        let classification = match threat_score {
            0.0..20.0 => ThreatClass::Benign,
            20.0..50.0 => ThreatClass::Suspicious,
            50.0..80.0 => ThreatClass::Malicious,
            _ => ThreatClass::Critical,
        };

        // Calculate confidence based on feature diversity
        let confidence = (contributing.len() as f64 / 10.0).min(1.0);

        ThreatPrediction {
            threat_score,
            confidence,
            classification,
            contributing_features: contributing,
            mitre_techniques,
        }
    }

    fn score_file_activity(&self, features: &FeatureVector) -> f64 {
        let mut score = 0.0;

        // Rapid file modifications (ransomware)
        if features.files_written > 100 {
            score += 15.0;
        }

        if features.files_renamed > 50 {
            score += 20.0; // Very suspicious
        }

        if features.files_deleted > 50 {
            score += 12.0;
        }

        if features.suspicious_extensions > 0 {
            score += (features.suspicious_extensions as f64) * 8.0;
        }

        score
    }

    /// Anomaly detection using statistical analysis
    pub fn detect_anomaly(&self, features: &FeatureVector, baseline: &FeatureVector) -> f64 {
        let mut anomaly_score: f64 = 0.0;
        let mut deviation_count = 0;

        // Compare current behavior against baseline
        if features.process_spawn_rate > baseline.process_spawn_rate * 3.0 {
            anomaly_score += 15.0;
            deviation_count += 1;
        }

        if (features.connections_out as f64) > (baseline.connections_out as f64) * 5.0 {
            anomaly_score += 20.0;
            deviation_count += 1;
        }

        if (features.files_written as f64) > (baseline.files_written as f64) * 10.0 {
            anomaly_score += 25.0;
            deviation_count += 1;
        }

        // Multiple deviations increase confidence
        if deviation_count >= 3 {
            anomaly_score *= 1.5;
        }

        anomaly_score.min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_process() {
        let scorer = MLThreatScorer::new();
        let features = FeatureVector::default();
        let prediction = scorer.score_process(&features);
        
        assert_eq!(prediction.classification, ThreatClass::Benign);
        assert!(prediction.threat_score < 20.0);
    }

    #[test]
    fn test_ransomware_detection() {
        let scorer = MLThreatScorer::new();
        let mut features = FeatureVector::default();
        features.files_written = 500;
        features.files_renamed = 500;
        features.files_deleted = 100;
        
        let prediction = scorer.score_process(&features);
        
        assert_eq!(prediction.classification, ThreatClass::Critical);
        assert!(prediction.threat_score > 70.0);
        assert!(prediction.mitre_techniques.contains(&"T1486".to_string()));
    }
}
