use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;

use crate::fim_engine::{FileBaseline, FIMViolation, FIMViolationType};
use crate::memory_analyzer::{MemoryAlert, MemoryAlertSeverity, MitreTechnique};

pub struct BackendClient {
    http: Client,
    base_url: String,
    endpoint_id: i32,
}

impl BackendClient {
    pub fn new(base_url: String, endpoint_id: i32) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("build backend http client")?;
        Ok(Self {
            http,
            base_url,
            endpoint_id,
        })
    }

    pub fn send_memory_alert(&self, alert: &MemoryAlert) -> Result<()> {
        #[derive(serde::Serialize)]
        struct MemoryAlertOut<'a> {
            severity: &'a str,
            title: &'a str,
            description: &'a str,
            mitre_techniques: &'a [MitreTechnique],
            source_pid: u32,
            source_image: &'a str,
            target_pid: Option<u32>,
            target_image: Option<&'a str>,
            address: Option<u64>,
            size: Option<u64>,
            old_protection: Option<u32>,
            new_protection: Option<u32>,
            timestamp: DateTime<Utc>,
            endpoint_id: i32,
        }

        let severity_str = match alert.severity {
            MemoryAlertSeverity::Low => "low",
            MemoryAlertSeverity::Medium => "medium",
            MemoryAlertSeverity::High => "high",
            MemoryAlertSeverity::Critical => "critical",
        };
        let ts = DateTime::<Utc>::from(alert.timestamp);
        let body = MemoryAlertOut {
            severity: severity_str,
            title: &alert.title,
            description: &alert.description,
            mitre_techniques: &alert.mitre_techniques,
            source_pid: alert.source_pid,
            source_image: &alert.source_image,
            target_pid: alert.target_pid,
            target_image: alert.target_image.as_deref(),
            address: alert.address,
            size: alert.size,
            old_protection: alert.old_protection,
            new_protection: alert.new_protection,
            timestamp: ts,
            endpoint_id: self.endpoint_id,
        };

        let url = format!("{}/edr/alerts/memory", self.base_url);
        self.http
            .post(url)
            .json(&body)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    pub fn send_fim_violation(&self, violation: &FIMViolation) -> Result<()> {
        #[derive(serde::Serialize)]
        struct FimViolationOut<'a> {
            path: &'a str,
            violation_type: &'a str,
            expected_hash: Option<&'a str>,
            actual_hash: Option<&'a str>,
            detected_at: DateTime<Utc>,
            endpoint_id: i32,
        }

        let detected_at = DateTime::<Utc>::from(violation.detected_at);
        let violation_type = match violation.violation_type {
            FIMViolationType::HashMismatch => "hash_mismatch",
            FIMViolationType::SizeChange => "size_change",
            FIMViolationType::UnauthorizedDeletion => "unauthorized_deletion",
            FIMViolationType::UnauthorizedCreation => "unauthorized_creation",
            FIMViolationType::PermissionChange => "permission_change",
            FIMViolationType::OwnershipChange => "ownership_change",
        };
        let body = FimViolationOut {
            path: &violation.path.to_string_lossy(),
            violation_type,
            expected_hash: violation.expected_hash.as_deref(),
            actual_hash: violation.actual_hash.as_deref(),
            detected_at,
            endpoint_id: self.endpoint_id,
        };

        let url = format!("{}/edr/alerts/fim", self.base_url);
        self.http
            .post(url)
            .json(&body)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    pub fn sync_fim_baseline(&self, baseline: &HashMap<PathBuf, FileBaseline>) -> Result<()> {
        #[derive(serde::Serialize)]
        struct FimBaselineEntry {
            path: String,
            sha256_hash: String,
            size: u64,
            modified_time: DateTime<Utc>,
            baseline_timestamp: DateTime<Utc>,
        }

        #[derive(serde::Serialize)]
        struct FimBaselineOut {
            endpoint_id: i32,
            entries: Vec<FimBaselineEntry>,
        }

        let entries = baseline
            .iter()
            .map(|(path, entry)| FimBaselineEntry {
                path: path.to_string_lossy().to_string(),
                sha256_hash: entry.sha256_hash.clone(),
                size: entry.size,
                modified_time: DateTime::<Utc>::from(entry.modified_time),
                baseline_timestamp: DateTime::<Utc>::from(entry.baseline_timestamp),
            })
            .collect::<Vec<_>>();

        let body = FimBaselineOut {
            endpoint_id: self.endpoint_id,
            entries,
        };

        let url = format!("{}/edr/baseline/fim", self.base_url);
        self.http
            .post(url)
            .json(&body)
            .send()?
            .error_for_status()?;
        Ok(())
    }
}
