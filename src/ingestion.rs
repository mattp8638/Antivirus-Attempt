use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::memory_analyzer::InjectionTechniqueHint;

#[derive(Debug, Clone)]
pub struct SensorEvent {
    pub ts_unix: u64,
    pub source: String,
    pub kind: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum MemoryEventRecord {
    Injection {
        ts_unix: u64,
        source_pid: u32,
        source_image: String,
        target_pid: u32,
        target_image: String,
        technique_hint: InjectionTechniqueHint,
    },
    MemProt {
        ts_unix: u64,
        pid: u32,
        process_image: String,
        address: u64,
        size: u64,
        old_protection: u32,
        new_protection: u32,
    },
    LsassAccess {
        ts_unix: u64,
        source_pid: u32,
        source_image: String,
        access_mask: u32,
    },
}

#[derive(Debug, Clone)]
pub struct MemoryIngestionResult {
    pub events: Vec<MemoryEventRecord>,
    pub parse_errors: usize,
}

pub fn ingest_memory_events_since(
    since_unix: u64,
    path: &Path,
    limit: usize,
) -> Result<MemoryIngestionResult, String> {
    if !path.exists() {
        return Ok(MemoryIngestionResult {
            events: Vec::new(),
            parse_errors: 0,
        });
    }

    let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut events = Vec::new();
    let mut parse_errors = 0usize;

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<MemoryEventRecord>(line) {
            Ok(event) => {
                let ts = match &event {
                    MemoryEventRecord::Injection { ts_unix, .. } => *ts_unix,
                    MemoryEventRecord::MemProt { ts_unix, .. } => *ts_unix,
                    MemoryEventRecord::LsassAccess { ts_unix, .. } => *ts_unix,
                };
                if ts >= since_unix {
                    events.push(event);
                }
            }
            Err(_) => {
                parse_errors += 1;
            }
        }
    }

    events.sort_by_key(|event| match event {
        MemoryEventRecord::Injection { ts_unix, .. } => *ts_unix,
        MemoryEventRecord::MemProt { ts_unix, .. } => *ts_unix,
        MemoryEventRecord::LsassAccess { ts_unix, .. } => *ts_unix,
    });

    if events.len() > limit {
        events = events[events.len() - limit..].to_vec();
    }

    Ok(MemoryIngestionResult {
        events,
        parse_errors,
    })
}

pub fn ingest_kernel_events_since(
    since_unix: u64,
    keywords: &[String],
    limit: usize,
    enable_audit_search: bool,
) -> Result<Vec<SensorEvent>, String> {
    let mut events = Vec::new();

    if enable_audit_search {
        let audit_events = ingest_auditd_events(since_unix, keywords, limit)?;
        events.extend(audit_events);
    }

    let journal_events = ingest_journalctl_kernel_events(since_unix, keywords, limit)?;
    events.extend(journal_events);

    if events.is_empty() {
        let dmesg_events = ingest_dmesg_kernel_events(keywords, limit)?;
        events.extend(dmesg_events);
    }

    events.sort_by_key(|e| e.ts_unix);
    if events.len() > limit {
        events = events[events.len() - limit..].to_vec();
    }

    Ok(events)
}

#[cfg(windows)]
pub fn ingest_windows_events_since(
    since_unix: u64,
    channels: &[String],
    event_ids: &[u32],
    limit: usize,
) -> Result<Vec<SensorEvent>, String> {
    let mut events = Vec::new();
    for channel in channels {
        let query = build_windows_query(since_unix, event_ids);
        let mut args = vec![
            "qe".to_string(),
            channel.to_string(),
            "/f:xml".to_string(),
            "/rd:true".to_string(),
            format!("/c:{limit}"),
        ];
        if let Some(q) = query {
            args.push(format!("/q:{q}"));
        }
        let output = Command::new("wevtutil")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            continue;
        }
        let data = String::from_utf8_lossy(&output.stdout);
        for block in data.split("</Event>") {
            if let Some(event) = parse_windows_event_xml(block, channel) {
                events.push(event);
                if events.len() >= limit {
                    break;
                }
            }
        }
        if events.len() >= limit {
            break;
        }
    }
    events.sort_by_key(|e| e.ts_unix);
    Ok(events)
}

#[cfg(not(windows))]
pub fn ingest_windows_events_since(
    _since_unix: u64,
    _channels: &[String],
    _event_ids: &[u32],
    _limit: usize,
) -> Result<Vec<SensorEvent>, String> {
    Ok(Vec::new())
}

fn ingest_auditd_events(
    since_unix: u64,
    keywords: &[String],
    limit: usize,
) -> Result<Vec<SensorEvent>, String> {
    let since = format!("{}", since_unix);
    let output = Command::new("ausearch")
        .args(["-ts", &since])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(mut event) = parse_kernel_line(line, keywords, "auditd") {
            event.kind = "audit_signal".to_string();
            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }

    Ok(events)
}

fn ingest_journalctl_kernel_events(
    since_unix: u64,
    keywords: &[String],
    limit: usize,
) -> Result<Vec<SensorEvent>, String> {
    let since = format!("@{}", since_unix);
    let output = Command::new("journalctl")
        .args(["-k", "--since", &since, "--no-pager", "-o", "short-unix"])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(event) = parse_kernel_line(line, keywords, "journalctl") {
            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }

    Ok(events)
}

fn ingest_dmesg_kernel_events(
    keywords: &[String],
    limit: usize,
) -> Result<Vec<SensorEvent>, String> {
    let output = Command::new("dmesg")
        .args(["--kernel", "--time-format", "unix"])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines().rev() {
        if let Some(event) = parse_kernel_line(line, keywords, "dmesg") {
            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }

    events.reverse();
    Ok(events)
}

fn parse_kernel_line(line: &str, keywords: &[String], source: &str) -> Option<SensorEvent> {
    let lower = line.to_lowercase();
    if !keywords.iter().any(|kw| lower.contains(kw)) {
        return None;
    }

    let ts_unix = extract_unix_timestamp(line).unwrap_or(0);
    let (kind, severity) = classify_kernel_event(&lower);
    Some(SensorEvent {
        ts_unix,
        source: source.to_string(),
        kind,
        severity,
        message: line.trim().to_string(),
    })
}

fn classify_kernel_event(line_lower: &str) -> (String, String) {
    if line_lower.contains("panic") || line_lower.contains("oops") {
        return ("kernel_panic".to_string(), "critical".to_string());
    }
    if line_lower.contains("segfault") || line_lower.contains("taint") {
        return ("kernel_integrity".to_string(), "high".to_string());
    }
    if line_lower.contains("denied")
        || line_lower.contains("apparmor")
        || line_lower.contains("selinux")
    {
        return ("kernel_policy".to_string(), "medium".to_string());
    }
    if line_lower.contains("oom") {
        return ("kernel_oom".to_string(), "medium".to_string());
    }
    ("kernel_signal".to_string(), "low".to_string())
}

fn extract_unix_timestamp(line: &str) -> Option<u64> {
    let first = line.split_whitespace().next()?;
    if let Ok(v) = first.parse::<f64>() {
        return Some(v as u64);
    }

    let cleaned = first.trim_matches('[').trim_matches(']');
    if let Ok(v) = cleaned.parse::<f64>() {
        return Some(v as u64);
    }

    None
}

fn parse_windows_event_xml(xml: &str, channel: &str) -> Option<SensorEvent> {
    let event_id = extract_between(xml, "<EventID>", "</EventID>")?
        .trim()
        .parse::<u32>()
        .ok()?;
    let system_time = extract_attr(xml, "SystemTime")?;
    let ts_unix = parse_rfc3339_to_unix(&system_time).unwrap_or(0);
    let provider = extract_attr(xml, "Name").unwrap_or_else(|| "windows".to_string());
    let record_id = extract_between(xml, "<EventRecordID>", "</EventRecordID>")
        .unwrap_or_else(|| "0".to_string());
    let computer =
        extract_between(xml, "<Computer>", "</Computer>").unwrap_or_else(|| "unknown".to_string());
    let level = extract_between(xml, "<Level>", "</Level>").unwrap_or_else(|| "4".to_string());
    let severity = match level.trim() {
        "1" | "2" => "critical",
        "3" => "high",
        "4" => "medium",
        _ => "low",
    };
    let details = build_windows_event_details(xml, event_id);
    let detail_suffix = if details.is_empty() {
        String::new()
    } else {
        format!(" {}", details.join(" "))
    };
    Some(SensorEvent {
        ts_unix,
        source: provider,
        kind: format!("windows_event:{event_id}"),
        severity: severity.to_string(),
        message: format!(
            "channel={} event_id={} record_id={} computer={}{}",
            channel,
            event_id,
            record_id.trim(),
            computer.trim(),
            detail_suffix
        ),
    })
}

fn extract_between(input: &str, start: &str, end: &str) -> Option<String> {
    let s_idx = input.find(start)? + start.len();
    let e_idx = input[s_idx..].find(end)? + s_idx;
    Some(input[s_idx..e_idx].to_string())
}

fn extract_attr(input: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = input.find(&needle)? + needle.len();
    let end = input[start..].find('"')? + start;
    Some(input[start..end].to_string())
}

fn extract_event_data_field(input: &str, field: &str) -> Option<String> {
    let needle = format!("Name=\"{field}\">");
    let start = input.find(&needle)? + needle.len();
    let end = input[start..].find("</Data>")? + start;
    let value = input[start..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn build_windows_event_details(xml: &str, event_id: u32) -> Vec<String> {
    let mut fields = Vec::new();
    match event_id {
        1 | 4688 => {
            fields.push(("image", "Image"));
            fields.push(("cmd", "CommandLine"));
            fields.push(("parent", "ParentImage"));
            fields.push(("user", "User"));
        }
        5 | 4689 => {
            fields.push(("image", "Image"));
            fields.push(("pid", "ProcessId"));
        }
        3 => {
            fields.push(("image", "Image"));
            fields.push(("dst_ip", "DestinationIp"));
            fields.push(("dst_port", "DestinationPort"));
            fields.push(("dst_host", "DestinationHostname"));
        }
        11 => {
            fields.push(("image", "Image"));
            fields.push(("target", "TargetFilename"));
        }
        6 => {
            fields.push(("driver", "ImageLoaded"));
            fields.push(("signed", "Signed"));
            fields.push(("signature", "Signature"));
            fields.push(("hashes", "Hashes"));
        }
        7 => {
            fields.push(("image", "Image"));
            fields.push(("module", "ImageLoaded"));
            fields.push(("signed", "Signed"));
            fields.push(("signature", "Signature"));
            fields.push(("hashes", "Hashes"));
        }
        8 => {
            fields.push(("src_image", "SourceImage"));
            fields.push(("src_pid", "SourceProcessId"));
            fields.push(("target_image", "TargetImage"));
            fields.push(("target_pid", "TargetProcessId"));
            fields.push(("start_addr", "StartAddress"));
            fields.push(("start_module", "StartModule"));
        }
        9 => {
            fields.push(("image", "Image"));
            fields.push(("device", "Device"));
        }
        10 => {
            fields.push(("src_image", "SourceImage"));
            fields.push(("target_image", "TargetImage"));
            fields.push(("granted", "GrantedAccess"));
            fields.push(("call_trace", "CallTrace"));
        }
        12 | 13 | 14 => {
            fields.push(("target", "TargetObject"));
            fields.push(("event_type", "EventType"));
            fields.push(("details", "Details"));
        }
        15 => {
            fields.push(("target", "TargetFilename"));
            fields.push(("hash", "Hash"));
            fields.push(("contents", "Contents"));
        }
        22 => {
            fields.push(("image", "Image"));
            fields.push(("query", "QueryName"));
            fields.push(("status", "QueryStatus"));
            fields.push(("results", "QueryResults"));
        }
        _ => {}
    }

    fields
        .into_iter()
        .filter_map(|(key, name)| {
            extract_event_data_field(xml, name).map(|val| format!("{key}={val}"))
        })
        .collect()
}

#[cfg(windows)]
fn build_windows_query(since_unix: u64, event_ids: &[u32]) -> Option<String> {
    if since_unix == 0 && event_ids.is_empty() {
        return None;
    }
    let mut conditions = Vec::new();
    if !event_ids.is_empty() {
        let id_expr = event_ids
            .iter()
            .map(|id| format!("EventID={id}"))
            .collect::<Vec<_>>()
            .join(" or ");
        conditions.push(format!("({id_expr})"));
    }
    if since_unix > 0 {
        let since = unix_to_rfc3339(since_unix)?;
        conditions.push(format!("TimeCreated[@SystemTime>='{since}']"));
    }
    let cond = conditions.join(" and ");
    Some(format!("\"*[System[{cond}]]\""))
}

fn parse_rfc3339_to_unix(value: &str) -> Option<u64> {
    let trimmed = value.trim_end_matches('Z').trim();
    let mut parts = trimmed.split('T');
    let date = parts.next()?;
    let time = parts.next()?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i32>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    let time_main = time.split('.').next().unwrap_or(time);
    let mut time_parts = time_main.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let second = time_parts.next()?.parse::<u32>().ok()?;
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    if seconds < 0 {
        None
    } else {
        Some(seconds as u64)
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) as i64)
}

#[cfg(windows)]
fn unix_to_rfc3339(ts_unix: u64) -> Option<String> {
    let days = (ts_unix / 86_400) as i64;
    let seconds_of_day = (ts_unix % 86_400) as u32;
    let (year, month, day) = civil_from_days(days)?;
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.0000000Z",
        year, month, day, hour, minute, second
    ))
}

#[cfg(windows)]
fn civil_from_days(days: i64) -> Option<(i32, u32, u32)> {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    Some((y as i32 + if m <= 2 { 1 } else { 0 }, m as u32, d as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_line_filters_keywords() {
        let kws = vec!["taint".to_string(), "segfault".to_string()];
        let line = "1710000000.12 kernel: process segfault at 0 ip ...";
        let event = parse_kernel_line(line, &kws, "journalctl").expect("expected event");
        assert_eq!(event.ts_unix, 1710000000);
        assert_eq!(event.kind, "kernel_integrity");
        assert_eq!(event.severity, "high");
    }

    #[test]
    fn parse_kernel_line_ignores_non_matches() {
        let kws = vec!["oom".to_string()];
        let line = "1710000000.12 kernel: harmless log";
        assert!(parse_kernel_line(line, &kws, "journalctl").is_none());
    }

    #[test]
    fn classify_panic() {
        let (kind, sev) = classify_kernel_event("kernel panic - not syncing");
        assert_eq!(kind, "kernel_panic");
        assert_eq!(sev, "critical");
    }

    #[test]
    fn parse_windows_event_xml_extracts_fields() {
        let xml = r#"
        <Event>
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4688</EventID>
            <EventRecordID>42</EventRecordID>
            <Level>4</Level>
            <TimeCreated SystemTime="2024-01-01T12:00:00.0000000Z"/>
            <Computer>HOST01</Computer>
          </System>
          <EventData>
            <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
            <Data Name="CommandLine">cmd.exe /c whoami</Data>
            <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
            <Data Name="User">DOMAIN\User</Data>
          </EventData>
        </Event>
        "#;
        let event = parse_windows_event_xml(xml, "Security").expect("event");
        assert_eq!(event.kind, "windows_event:4688");
        assert_eq!(event.severity, "medium");
        assert!(event.message.contains("record_id=42"));
        assert!(event.message.contains("computer=HOST01"));
        assert!(event
            .message
            .contains("image=C:\\Windows\\System32\\cmd.exe"));
        assert!(event.message.contains("cmd=cmd.exe /c whoami"));
        assert!(event.message.contains("parent=C:\\Windows\\explorer.exe"));
        assert!(event.message.contains("user=DOMAIN\\User"));
        assert!(event.ts_unix > 0);
    }

    #[cfg(windows)]
    #[test]
    fn unix_to_rfc3339_formats_epoch() {
        let ts = unix_to_rfc3339(0).expect("ts");
        assert_eq!(ts, "1970-01-01T00:00:00.0000000Z");
    }
}
