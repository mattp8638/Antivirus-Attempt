use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use crate::models::{Alert, Incident};
use serde_json;

pub fn publish_or_spool(
    endpoint: &str,
    api_key: &str,
    spool_path: &Path,
    tenant_id: &str,
    endpoint_id: &str,
    ts: u64,
    alerts: &[Alert],
    incidents: &[Incident],
) -> Result<(), String> {
    flush_spool(endpoint, api_key, spool_path)?;

    let payload = build_batch_json(ts, tenant_id, endpoint_id, alerts, incidents);
    match post_json(endpoint, api_key, &payload) {
        Ok(()) => Ok(()),
        Err(err) => {
            append_spool(spool_path, &payload)?;
            Err(err)
        }
    }
}

pub fn write_heartbeat(
    path: &Path,
    ts: u64,
    alert_count: usize,
    incident_count: usize,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(
        f,
        "{{\"ts\":{},\"alert_count\":{},\"incident_count\":{}}}",
        ts, alert_count, incident_count
    )
    .map_err(|e| e.to_string())
}

fn flush_spool(endpoint: &str, api_key: &str, spool_path: &Path) -> Result<(), String> {
    if !spool_path.exists() {
        return Ok(());
    }

    let data = fs::read_to_string(spool_path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = data.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return Ok(());
    }

    for line in &lines {
        post_json(endpoint, api_key, line)?;
    }

    fs::write(spool_path, "").map_err(|e| e.to_string())?;
    Ok(())
}

fn post_json(endpoint: &str, api_key: &str, payload: &str) -> Result<(), String> {
    let (host_port, path) = split_endpoint(endpoint)?;
    let mut stream = TcpStream::connect(&host_port).map_err(|e| e.to_string())?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host_port,
        api_key,
        payload.len(),
        payload
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    if buf.starts_with("HTTP/1.1 2") || buf.starts_with("HTTP/1.0 2") {
        Ok(())
    } else {
        Err(format!(
            "telemetry endpoint rejected payload: {}",
            first_line(&buf)
        ))
    }
}

fn split_endpoint(endpoint: &str) -> Result<(String, String), String> {
    let cleaned = endpoint.trim();
    if cleaned.is_empty() {
        return Err("empty telemetry endpoint".into());
    }
    let mut parts = cleaned.splitn(2, '/');
    let host_port = parts.next().ok_or("invalid endpoint")?.to_string();
    let path = format!("/{}", parts.next().unwrap_or("ingest"));
    Ok((host_port, path))
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn append_spool(path: &Path, payload: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{}", payload).map_err(|e| e.to_string())
}

pub fn build_batch_json(
    ts: u64,
    tenant_id: &str,
    endpoint_id: &str,
    alerts: &[Alert],
    incidents: &[Incident],
) -> String {
    let alerts_json = alerts
        .iter()
        .map(|a| {
            let tags_json = if a.intel_tags.is_empty() {
                "[]".to_string()
            } else {
                format!(
                    "[{}]",
                    a.intel_tags
                        .iter()
                        .map(|t| format!("\"{}\"", escape(t)))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            let details_json = match &a.details {
                Some(details) => serde_json::to_string(details).unwrap_or_else(|_| "null".into()),
                None => "null".to_string(),
            };
            format!(
                "{{\"rule\":\"{}\",\"severity\":\"{}\",\"message\":\"{}\",\"pid\":{},\"attack_tactic\":{},\"attack_technique\":{},\"intel_tags\":{},\"details\":{}}}",
                escape(&a.rule),
                escape(&a.severity),
                escape(&a.message),
                a.pid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
                ,
                a.attack_tactic
                    .as_ref()
                    .map(|v| format!("\"{}\"", escape(v)))
                    .unwrap_or_else(|| "null".to_string()),
                a.attack_technique
                    .as_ref()
                    .map(|v| format!("\"{}\"", escape(v)))
                    .unwrap_or_else(|| "null".to_string()),
                tags_json,
                details_json
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let incidents_json = incidents
        .iter()
        .map(|i| {
            format!(
                "{{\"incident_id\":\"{}\",\"pid\":{},\"risk_score\":{},\"alert_count\":{},\"summary\":\"{}\"}}",
                escape(&i.incident_id),
                i.primary_pid,
                i.risk_score,
                i.alert_count,
                escape(&i.summary)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"ts\":{},\"tenant_id\":\"{}\",\"endpoint_id\":\"{}\",\"alerts\":[{}],\"incidents\":[{}]}}",
        ts,
        escape(tenant_id),
        escape(endpoint_id),
        alerts_json,
        incidents_json
    )
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Alert, Incident};
    use serde_json::json;

    #[test]
    fn builds_batch_json() {
        let alerts = vec![Alert::with_pid("r", "high", "msg".into(), 1)];
        let incidents = vec![Incident {
            incident_id: "inc-1".into(),
            primary_pid: 1,
            risk_score: 11,
            alert_count: 2,
            summary: "test".into(),
        }];
        let body = build_batch_json(100, "tenant-a", "endpoint-1", &alerts, &incidents);
        assert!(body.contains("\"alerts\""));
        assert!(body.contains("\"incidents\""));
        assert!(body.contains("inc-1"));
        assert!(body.contains("\"tenant_id\""));
        assert!(body.contains("\"endpoint_id\""));
    }

    #[test]
    fn serializes_alert_details() {
        let mut alert = Alert::new("memory_injection_detected", "high", "hit".into());
        alert.set_details(json!({"source_pid": 10, "target_pid": 99}));
        let body = build_batch_json(100, "tenant-a", "endpoint-1", &[alert], &[]);
        assert!(body.contains("\"details\":{\"source_pid\":10,\"target_pid\":99}"));
    }
}
