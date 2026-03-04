use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct ServerConfig {
    bind: String,
    api_key: String,
    output_path: PathBuf,
    output_dir: Option<PathBuf>,
    error_log_path: PathBuf,
    max_body_bytes: usize,
    max_file_bytes: u64,
    split_alerts: bool,
    db_path: Option<PathBuf>,
}

fn main() -> Result<(), String> {
    let config = parse_args()?;
    if let Some(db_path) = &config.db_path {
        init_db(db_path)?;
    }
    let listener = TcpListener::bind(&config.bind).map_err(|e| e.to_string())?;
    eprintln!("ingest-server listening on {}", config.bind);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_connection(stream, &config) {
                    log_error(&config.error_log_path, &err)?;
                }
            }
            Err(err) => {
                log_error(&config.error_log_path, &format!("accept failed: {err}"))?;
            }
        }
    }
    Ok(())
}

fn parse_args() -> Result<ServerConfig, String> {
    let mut bind = "0.0.0.0:8080".to_string();
    let mut api_key = String::new();
    let mut output_path = PathBuf::from("ingest_events.jsonl");
    let mut output_dir: Option<PathBuf> = None;
    let mut error_log_path = PathBuf::from("ingest_errors.log");
    let mut max_body_bytes: usize = 2 * 1024 * 1024;
    let mut max_file_bytes: u64 = 50 * 1024 * 1024;
    let mut split_alerts = false;
    let mut db_path: Option<PathBuf> = None;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).ok_or("missing value for --bind")?.clone();
            }
            "--api-key" => {
                i += 1;
                api_key = args.get(i).ok_or("missing value for --api-key")?.clone();
            }
            "--output" => {
                i += 1;
                output_path = PathBuf::from(args.get(i).ok_or("missing value for --output")?);
            }
            "--output-dir" => {
                i += 1;
                output_dir = Some(PathBuf::from(
                    args.get(i).ok_or("missing value for --output-dir")?,
                ));
            }
            "--error-log" => {
                i += 1;
                error_log_path = PathBuf::from(args.get(i).ok_or("missing value for --error-log")?);
            }
            "--max-body-bytes" => {
                i += 1;
                max_body_bytes = args
                    .get(i)
                    .ok_or("missing value for --max-body-bytes")?
                    .parse::<usize>()
                    .map_err(|_| "invalid --max-body-bytes")?;
            }
            "--max-file-bytes" => {
                i += 1;
                max_file_bytes = args
                    .get(i)
                    .ok_or("missing value for --max-file-bytes")?
                    .parse::<u64>()
                    .map_err(|_| "invalid --max-file-bytes")?;
            }
            "--split-output" => split_alerts = true,
            "--db-path" => {
                i += 1;
                db_path = Some(PathBuf::from(args.get(i).ok_or("missing value for --db-path")?));
            }
            _ => return Err(format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }

    if api_key.trim().is_empty() {
        return Err("--api-key is required".into());
    }

    Ok(ServerConfig {
        bind,
        api_key,
        output_path,
        output_dir,
        error_log_path,
        max_body_bytes,
        max_file_bytes,
        split_alerts,
        db_path,
    })
}

fn handle_connection(mut stream: TcpStream, config: &ServerConfig) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut buffer = Vec::new();
    let mut temp = [0u8; 4096];
    loop {
        let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > config.max_body_bytes {
            respond(&mut stream, 413, "payload too large")?;
            return Err("request header too large".into());
        }
    }

    let header_end = find_header_end(&buffer).ok_or("invalid HTTP request")?;
    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
    let mut headers = header_str.lines();
    let request_line = headers.next().ok_or("missing request line")?;
    let (method, path) = parse_request_line(request_line)?;
    if method != "POST" {
        respond(&mut stream, 405, "method not allowed")?;
        return Err(format!("unexpected method {method}"));
    }
    if path != "/api/v1/ingest/edr" {
        respond(&mut stream, 404, "not found")?;
        return Err(format!("unexpected path {path}"));
    }

    let mut content_length: Option<usize> = None;
    let mut auth_ok = false;
    for line in headers {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            content_length = value.parse::<usize>().ok();
        }
        if lower.starts_with("authorization:") {
            let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            let expected = format!("Bearer {}", config.api_key);
            if value == expected {
                auth_ok = true;
            }
        }
    }

    if !auth_ok {
        respond(&mut stream, 401, "unauthorized")?;
        return Err("unauthorized request".into());
    }

    let content_length = content_length.ok_or("missing Content-Length")?;
    if content_length > config.max_body_bytes {
        respond(&mut stream, 413, "payload too large")?;
        return Err("payload too large".into());
    }

    let mut body = Vec::new();
    if buffer.len() > header_end + 4 {
        body.extend_from_slice(&buffer[header_end + 4..]);
    }
    while body.len() < content_length {
        let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&temp[..n]);
        if body.len() > config.max_body_bytes {
            respond(&mut stream, 413, "payload too large")?;
            return Err("payload exceeded limit".into());
        }
    }

    let payload = String::from_utf8(body).map_err(|_| "payload not valid UTF-8")?;
    let (tenant_id, endpoint_id) = validate_payload(&payload)?;
    let output_path = resolve_output_path(config, &tenant_id, &endpoint_id);
    append_payload(&output_path, &payload, config.max_file_bytes)?;
    if config.split_alerts {
        write_split_payload(config, &tenant_id, &endpoint_id, &payload)?;
    }
    write_stats(config, &tenant_id, &endpoint_id, &payload)?;
    write_endpoint_index(config, &tenant_id, &endpoint_id, &payload)?;
    write_rule_index(config, &tenant_id, &payload)?;
    write_rule_stats(config, &tenant_id, &payload)?;
    write_rule_rollups(config, &tenant_id, &payload)?;
    write_tenant_summary(config, &tenant_id, &payload)?;
    write_tenant_rollups(config, &tenant_id, &payload)?;
    if let Some(db_path) = &config.db_path {
        if let Err(err) = store_payload_to_db(db_path, &tenant_id, &endpoint_id, &payload) {
            respond(&mut stream, 500, "db write failed")?;
            return Err(err);
        }
    }
    respond(&mut stream, 200, "ok")?;
    Ok(())
}

fn parse_request_line(line: &str) -> Result<(&str, &str), String> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("invalid request line")?;
    let path = parts.next().ok_or("invalid request line")?;
    Ok((method, path))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text(status),
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).map_err(|e| e.to_string())
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn validate_payload(payload: &str) -> Result<(String, String), String> {
    let tenant_id =
        extract_json_string_field(payload, "tenant_id").ok_or("payload missing tenant_id")?;
    let endpoint_id =
        extract_json_string_field(payload, "endpoint_id").ok_or("payload missing endpoint_id")?;
    if tenant_id.trim().is_empty() {
        return Err("tenant_id must be non-empty".into());
    }
    if endpoint_id.trim().is_empty() {
        return Err("endpoint_id must be non-empty".into());
    }
    if extract_json_number_field(payload, "ts").is_none() {
        return Err("payload missing ts".into());
    }
    if !payload.contains("\"alerts\"") && !payload.contains("\"incidents\"") {
        return Err("payload missing alerts/incidents".into());
    }
    let alerts = extract_json_array(payload, "alerts");
    validate_alert_objects(&alerts)?;
    let incidents = extract_json_array(payload, "incidents");
    validate_incident_objects(&incidents)?;
    Ok((tenant_id, endpoint_id))
}

fn init_db(path: &PathBuf) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let schema = "CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            pid INTEGER,
            attack_tactic TEXT,
            attack_technique TEXT,
            intel_tags TEXT,
            details TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts (tenant_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_endpoint ON alerts (endpoint_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule);
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            pid INTEGER,
            risk_score INTEGER NOT NULL,
            alert_count INTEGER NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents (ts);
        CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents (tenant_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_endpoint ON incidents (endpoint_id);";
    run_sqlite(path, schema)?;
    ensure_alerts_details_column(path)?;
    Ok(())
}

fn ensure_alerts_details_column(path: &PathBuf) -> Result<(), String> {
    if !has_alerts_column(path, "details")? {
        run_sqlite(path, "ALTER TABLE alerts ADD COLUMN details TEXT;")?;
    }
    Ok(())
}

fn has_alerts_column(path: &PathBuf, column: &str) -> Result<bool, String> {
    let output = Command::new("sqlite3")
        .arg(path)
        .arg("-batch")
        .arg("PRAGMA table_info(alerts);")
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sqlite3 failed: {}", err.trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut parts = line.split('|');
        let _cid = parts.next();
        let name = parts.next();
        if name == Some(column) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn store_payload_to_db(
    path: &PathBuf,
    tenant_id: &str,
    endpoint_id: &str,
    payload: &str,
) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0) as i64;
    let alerts = extract_json_array(payload, "alerts");
    let incidents = extract_json_array(payload, "incidents");
    let mut sql = String::new();
    sql.push_str("BEGIN IMMEDIATE;");
    for alert in &alerts {
        let rule = extract_json_string_field(alert, "rule").unwrap_or_else(|| "unknown".into());
        let severity =
            extract_json_string_field(alert, "severity").unwrap_or_else(|| "unknown".into());
        let message = extract_json_string_field(alert, "message").unwrap_or_default();
        let pid = extract_json_number_field(alert, "pid").map(|v| v as i64);
        let attack_tactic = extract_json_string_field(alert, "attack_tactic");
        let attack_technique = extract_json_string_field(alert, "attack_technique");
        let intel_tags = extract_json_array_raw(alert, "intel_tags").unwrap_or("[]".to_string());
        let details_raw = extract_json_value_raw(alert, "details");
        if alert.contains("\"details\"") && details_raw.is_none() {
            return Err("alert details malformed".into());
        }
        let details_value = match details_raw.as_deref() {
            Some("null") | None => "NULL".to_string(),
            Some(v) => sqlite_value(v),
        };
        sql.push_str(&format!(
            "INSERT INTO alerts (ts, tenant_id, endpoint_id, rule, severity, message, pid, attack_tactic, attack_technique, intel_tags, details) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
            ts,
            sqlite_value(tenant_id),
            sqlite_value(endpoint_id),
            sqlite_value(&rule),
            sqlite_value(&severity),
            sqlite_value(&message),
            sqlite_opt_number(pid),
            sqlite_opt_value(attack_tactic.as_deref()),
            sqlite_opt_value(attack_technique.as_deref()),
            sqlite_value(&intel_tags),
            details_value
        ));
    }
    for incident in &incidents {
        let incident_id = extract_json_string_field(incident, "incident_id")
            .unwrap_or_else(|| "unknown".into());
        let pid = extract_json_number_field(incident, "pid").map(|v| v as i64);
        let risk_score = extract_json_number_field(incident, "risk_score").unwrap_or(0) as i64;
        let alert_count = extract_json_number_field(incident, "alert_count").unwrap_or(0) as i64;
        let summary = extract_json_string_field(incident, "summary").unwrap_or_default();
        sql.push_str(&format!(
            "INSERT INTO incidents (ts, tenant_id, endpoint_id, incident_id, pid, risk_score, alert_count, summary) VALUES ({}, {}, {}, {}, {}, {}, {}, {});",
            ts,
            sqlite_value(tenant_id),
            sqlite_value(endpoint_id),
            sqlite_value(&incident_id),
            sqlite_opt_number(pid),
            risk_score,
            alert_count,
            sqlite_value(&summary)
        ));
    }
    sql.push_str("COMMIT;");
    run_sqlite(path, &sql)?;
    Ok(())
}

fn run_sqlite(path: &PathBuf, sql: &str) -> Result<(), String> {
    let mut child = Command::new("sqlite3")
        .arg(path)
        .arg("-batch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(sql.as_bytes()).map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sqlite3 failed: {}", err.trim()));
    }
    Ok(())
}

fn sqlite_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sqlite_opt_value(value: Option<&str>) -> String {
    match value {
        Some(v) => sqlite_value(v),
        None => "NULL".to_string(),
    }
}

fn sqlite_opt_number(value: Option<i64>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "NULL".to_string(),
    }
}

fn resolve_output_base(config: &ServerConfig, tenant_id: &str, endpoint_id: &str) -> PathBuf {
    if let Some(dir) = &config.output_dir {
        let safe_tenant = sanitize_segment(tenant_id);
        let safe_endpoint = sanitize_segment(endpoint_id);
        return dir.join(safe_tenant).join(safe_endpoint);
    }
    PathBuf::from(".")
}

fn resolve_output_path(config: &ServerConfig, tenant_id: &str, endpoint_id: &str) -> PathBuf {
    if config.output_dir.is_some() {
        return resolve_output_base(config, tenant_id, endpoint_id).join("ingest.jsonl");
    }
    config.output_path.clone()
}

fn extract_json_string_field(payload: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = payload.find(&needle)? + needle.len();
    let remainder = &payload[start..];
    let colon = remainder.find(':')? + 1;
    let mut value = remainder[colon..].trim_start();
    if !value.starts_with('"') {
        return None;
    }
    value = &value[1..];
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn extract_json_number_field(payload: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let start = payload.find(&needle)? + needle.len();
    let remainder = &payload[start..];
    let colon = remainder.find(':')? + 1;
    let mut value = remainder[colon..].trim_start();
    let end = value
        .find(|ch: char| ch == ',' || ch == '}' || ch.is_whitespace())
        .unwrap_or(value.len());
    value = &value[..end];
    value.parse::<u64>().ok()
}

fn extract_json_value_raw(payload: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = payload.find(&needle)? + needle.len();
    let remainder = &payload[start..];
    let colon_pos = remainder.find(':')? + start;
    let bytes = payload.as_bytes();
    let mut idx = colon_pos + 1;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }
    match bytes[idx] as char {
        '{' => extract_bracketed(payload, idx, '{', '}'),
        '[' => extract_bracketed(payload, idx, '[', ']'),
        'n' => {
            if payload[idx..].starts_with("null") {
                Some("null".to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn sanitize_segment(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.trim_matches('_').is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_details_object() {
        let payload = r#"{"rule":"x","details":{"source_pid":10,"target_pid":99},"message":"m"}"#;
        let raw = extract_json_value_raw(payload, "details").expect("details missing");
        assert_eq!(raw, r#"{"source_pid":10,"target_pid":99}"#);
    }

    #[test]
    fn extracts_details_null() {
        let payload = r#"{"rule":"x","details":null,"message":"m"}"#;
        let raw = extract_json_value_raw(payload, "details").expect("details missing");
        assert_eq!(raw, "null");
    }

    #[test]
    fn extracts_details_array() {
        let payload = r#"{"rule":"x","details":[{"k":"v"}],"message":"m"}"#;
        let raw = extract_json_value_raw(payload, "details").expect("details missing");
        assert_eq!(raw, r#"[{"k":"v"}]"#);
    }

    #[test]
    fn rejects_invalid_details_value() {
        let alert = r#"{"rule":"x","severity":"low","message":"m","details":"oops"}"#;
        let result = validate_alert_objects(&[alert.to_string()]);
        assert!(result.is_err());
    }
}

fn append_payload(path: &PathBuf, payload: &str, max_file_bytes: u64) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    rotate_if_needed(path, max_file_bytes)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{}", payload).map_err(|e| e.to_string())
}

fn write_split_payload(
    config: &ServerConfig,
    tenant_id: &str,
    endpoint_id: &str,
    payload: &str,
) -> Result<(), String> {
    let alerts = extract_json_array(payload, "alerts");
    let incidents = extract_json_array(payload, "incidents");
    let base = resolve_output_base(config, tenant_id, endpoint_id);
    if !alerts.is_empty() {
        let alerts_path = base.join("alerts.jsonl");
        append_lines(&alerts_path, &alerts, config.max_file_bytes)?;
        write_alert_type_logs(&base, &alerts, config.max_file_bytes)?;
    }
    if !incidents.is_empty() {
        let incidents_path = base.join("incidents.jsonl");
        append_lines(&incidents_path, &incidents, config.max_file_bytes)?;
    }
    Ok(())
}

fn write_stats(
    config: &ServerConfig,
    tenant_id: &str,
    endpoint_id: &str,
    payload: &str,
) -> Result<(), String> {
    let base = resolve_output_base(config, tenant_id, endpoint_id);
    let alerts = extract_json_array(payload, "alerts");
    let incidents = extract_json_array(payload, "incidents");
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let line = format!(
        "{{\"ts\":{},\"alert_count\":{},\"incident_count\":{}}}",
        ts,
        alerts.len(),
        incidents.len()
    );
    let stats_path = base.join("stats.jsonl");
    append_lines(&stats_path, &[line], config.max_file_bytes)
}

fn write_endpoint_index(
    config: &ServerConfig,
    tenant_id: &str,
    endpoint_id: &str,
    payload: &str,
) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let line = format!(
        "{{\"ts\":{},\"endpoint_id\":\"{}\"}}",
        ts,
        sanitize_segment(endpoint_id)
    );
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let index_path = base.join("endpoints.jsonl");
    append_lines(&index_path, &[line], config.max_file_bytes)
}

fn write_rule_index(config: &ServerConfig, tenant_id: &str, payload: &str) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let alerts = extract_json_array(payload, "alerts");
    let mut lines = Vec::new();
    for alert in alerts {
        if let Some(rule) = extract_json_string_field(&alert, "rule") {
            lines.push(format!("{{\"ts\":{},\"rule\":\"{}\"}}", ts, rule));
        }
    }
    if lines.is_empty() {
        return Ok(());
    }
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let rules_path = base.join("rules.jsonl");
    append_lines(&rules_path, &lines, config.max_file_bytes)
}

fn write_rule_stats(config: &ServerConfig, tenant_id: &str, payload: &str) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let alerts = extract_json_array(payload, "alerts");
    let mut entries: Vec<(String, usize)> = Vec::new();
    for alert in alerts {
        if let Some(rule) = extract_json_string_field(&alert, "rule") {
            if let Some(existing) = entries.iter_mut().find(|(r, _)| *r == rule) {
                existing.1 += 1;
            } else {
                entries.push((rule, 1));
            }
        }
    }
    if entries.is_empty() {
        return Ok(());
    }
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let stats_path = base.join("rule_stats.jsonl");
    let lines = entries
        .into_iter()
        .map(|(rule, count)| format!("{{\"ts\":{},\"rule\":\"{}\",\"count\":{}}}", ts, rule, count))
        .collect::<Vec<_>>();
    append_lines(&stats_path, &lines, config.max_file_bytes)
}

fn write_rule_rollups(
    config: &ServerConfig,
    tenant_id: &str,
    payload: &str,
) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let alerts = extract_json_array(payload, "alerts");
    let mut entries: Vec<(String, usize)> = Vec::new();
    for alert in alerts {
        if let Some(rule) = extract_json_string_field(&alert, "rule") {
            if let Some(existing) = entries.iter_mut().find(|(r, _)| *r == rule) {
                existing.1 += 1;
            } else {
                entries.push((rule, 1));
            }
        }
    }
    if entries.is_empty() {
        return Ok(());
    }
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let hour = ts / 3600;
    let lines = entries
        .into_iter()
        .map(|(rule, count)| {
            format!(
                "{{\"ts\":{},\"hour_bucket\":{},\"rule\":\"{}\",\"count\":{}}}",
                ts, hour, rule, count
            )
        })
        .collect::<Vec<_>>();
    let rollup_path = base.join("rule_rollups.jsonl");
    append_lines(&rollup_path, &lines, config.max_file_bytes)
}

fn write_tenant_summary(
    config: &ServerConfig,
    tenant_id: &str,
    payload: &str,
) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let alerts = extract_json_array(payload, "alerts");
    let incidents = extract_json_array(payload, "incidents");
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let summary_path = base.join("tenant_summary.jsonl");
    let line = format!(
        "{{\"ts\":{},\"alert_count\":{},\"incident_count\":{}}}",
        ts,
        alerts.len(),
        incidents.len()
    );
    append_lines(&summary_path, &[line], config.max_file_bytes)
}

fn write_tenant_rollups(
    config: &ServerConfig,
    tenant_id: &str,
    payload: &str,
) -> Result<(), String> {
    let ts = extract_json_number_field(payload, "ts").unwrap_or(0);
    let alerts = extract_json_array(payload, "alerts");
    let incidents = extract_json_array(payload, "incidents");
    let hour = ts / 3600;
    let day_bucket = ts / 86_400;
    let line = format!(
        "{{\"ts\":{},\"hour_bucket\":{},\"day_bucket\":{},\"alert_count\":{},\"incident_count\":{}}}",
        ts,
        hour,
        day_bucket,
        alerts.len(),
        incidents.len()
    );
    let base = if let Some(dir) = &config.output_dir {
        dir.join(sanitize_segment(tenant_id))
    } else {
        PathBuf::from(".")
    };
    let rollup_path = base.join("tenant_rollups.jsonl");
    append_lines(&rollup_path, &[line], config.max_file_bytes)
}

fn append_lines(path: &PathBuf, lines: &[String], max_file_bytes: u64) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    rotate_if_needed(path, max_file_bytes)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    for line in lines {
        writeln!(file, "{}", line).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn write_alert_type_logs(
    base: &PathBuf,
    alerts: &[String],
    max_file_bytes: u64,
) -> Result<(), String> {
    let mut process = Vec::new();
    let mut network = Vec::new();
    let mut file = Vec::new();
    for alert in alerts {
        if let Some(rule) = extract_json_string_field(alert, "rule") {
            if rule.starts_with("windows_process") {
                process.push(alert.clone());
            } else if rule.starts_with("windows_network") {
                network.push(alert.clone());
            } else if rule.starts_with("windows_file") {
                file.push(alert.clone());
            }
        }
    }
    if !process.is_empty() {
        append_lines(&base.join("windows_process.jsonl"), &process, max_file_bytes)?;
    }
    if !network.is_empty() {
        append_lines(&base.join("windows_network.jsonl"), &network, max_file_bytes)?;
    }
    if !file.is_empty() {
        append_lines(&base.join("windows_file.jsonl"), &file, max_file_bytes)?;
    }
    Ok(())
}

fn extract_json_array(payload: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let start = match payload.find(&needle) {
        Some(pos) => pos + needle.len(),
        None => return Vec::new(),
    };
    let remainder = &payload[start..];
    let array_start = match remainder.find('[') {
        Some(pos) => start + pos,
        None => return Vec::new(),
    };
    let array = match extract_bracketed(payload, array_start, '[', ']') {
        Some(value) => value,
        None => return Vec::new(),
    };
    split_json_objects(&array)
}

fn extract_json_array_raw(payload: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = payload.find(&needle)? + needle.len();
    let remainder = &payload[start..];
    let array_start = remainder.find('[')? + start;
    extract_bracketed(payload, array_start, '[', ']')
}

fn validate_alert_objects(alerts: &[String]) -> Result<(), String> {
    for alert in alerts {
        if extract_json_string_field(alert, "rule").is_none() {
            return Err("alert missing rule".into());
        }
        if extract_json_string_field(alert, "severity").is_none() {
            return Err("alert missing severity".into());
        }
        if extract_json_string_field(alert, "message").is_none() {
            return Err("alert missing message".into());
        }
        if alert.contains("\"details\"") && extract_json_value_raw(alert, "details").is_none() {
            return Err("alert details malformed".into());
        }
    }
    Ok(())
}

fn validate_incident_objects(incidents: &[String]) -> Result<(), String> {
    for incident in incidents {
        if extract_json_string_field(incident, "incident_id").is_none() {
            return Err("incident missing incident_id".into());
        }
        if extract_json_number_field(incident, "risk_score").is_none() {
            return Err("incident missing risk_score".into());
        }
    }
    Ok(())
}

fn extract_bracketed(input: &str, start: usize, open: char, close: char) -> Option<String> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (idx, ch) in input[start..].char_indices() {
        if in_str {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
            continue;
        }
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                let end = start + idx + 1;
                return Some(input[start..end].to_string());
            }
        }
    }
    None
}

fn split_json_objects(array: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    let mut start = None;
    for (idx, ch) in array.char_indices() {
        if in_str {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
            continue;
        }
        if ch == '{' {
            if depth == 0 {
                start = Some(idx);
            }
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = start {
                    out.push(array[s..=idx].to_string());
                    start = None;
                }
            }
        }
    }
    out
}

fn rotate_if_needed(path: &PathBuf, max_file_bytes: u64) -> Result<(), String> {
    if max_file_bytes == 0 || !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() < max_file_bytes {
        return Ok(());
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let rotated = path.with_extension(format!("jsonl.{ts}"));
    fs::rename(path, rotated).map_err(|e| e.to_string())
}

fn log_error(path: &PathBuf, message: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{} {}", ts, message).map_err(|e| e.to_string())
}
