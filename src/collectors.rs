use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::models::{ConnectionInfo, ProcessInfo};
use sha2::{Digest, Sha256};

pub fn collect_processes(cpp_collector_path: &Path) -> Result<Vec<ProcessInfo>, String> {
    if cpp_collector_path.exists() {
        let output = Command::new(cpp_collector_path)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        let mut processes = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut parts = line.splitn(3, ' ');
            let pid = match parts.next().and_then(|v| v.parse::<i32>().ok()) {
                Some(v) => v,
                None => continue,
            };
            let name = match parts.next() {
                Some(v) => v.to_lowercase(),
                None => continue,
            };
            let command = parts.next().unwrap_or("").to_lowercase();
            processes.push(ProcessInfo {
                pid,
                ppid: 0,
                name,
                command,
            });
        }
        return Ok(processes);
    }

    let output = Command::new("ps")
        .args(["-eo", "pid=,ppid=,comm=,args="])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("ps command failed".into());
    }
    let mut processes = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let pid = match parts.next().and_then(|v| v.parse::<i32>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let ppid = match parts.next().and_then(|v| v.parse::<i32>().ok()) {
            Some(v) => v,
            None => 0,
        };
        let name = match parts.next() {
            Some(v) => v.to_lowercase(),
            None => continue,
        };
        let command = parts.collect::<Vec<_>>().join(" ").to_lowercase();
        processes.push(ProcessInfo {
            pid,
            ppid,
            name,
            command,
        });
    }
    Ok(processes)
}

pub fn collect_network_connections() -> Result<Vec<ConnectionInfo>, String> {
    let output = Command::new("ss")
        .args(["-tunpH"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let mut connections = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(conn) = parse_ss_line(line) {
            connections.push(conn);
        }
    }
    Ok(connections)
}

fn parse_ss_line(line: &str) -> Option<ConnectionInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }

    let protocol = parts[0].to_lowercase();
    let local = parts[parts.len() - 3];
    let remote = parts[parts.len() - 2];
    let process_chunk = line
        .split_once("users:(")
        .map(|(_, right)| {
            let mut s = String::from("users:(");
            s.push_str(right);
            s
        })
        .unwrap_or_default();

    let (local_address, local_port) = split_endpoint(local)?;
    let (remote_address, remote_port) = split_endpoint(remote)?;

    let pid = extract_pid(&process_chunk);
    let process_name = extract_proc_name(&process_chunk);

    Some(ConnectionInfo {
        protocol,
        local_address,
        local_port,
        remote_address: remote_address.to_lowercase(),
        remote_port,
        pid,
        process_name: process_name.map(|s| s.to_lowercase()),
    })
}

fn split_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let idx = endpoint.rfind(':')?;
    let host = endpoint[..idx]
        .trim_matches('[')
        .trim_matches(']')
        .to_string();
    let port_text = &endpoint[idx + 1..];
    let port = port_text.parse::<u16>().ok()?;
    Some((host, port))
}

fn extract_pid(chunk: &str) -> Option<i32> {
    let marker = "pid=";
    let start = chunk.find(marker)? + marker.len();
    let rest = &chunk[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<i32>().ok()
}

fn extract_proc_name(chunk: &str) -> Option<String> {
    let marker = "\"";
    let start = chunk.find(marker)? + 1;
    let rest = &chunk[start..];
    let end = rest.find(marker)?;
    Some(rest[..end].to_string())
}

pub fn build_file_snapshot(
    root: &Path,
    excluded_directory_names: &HashSet<String>,
    excluded_files: &HashSet<PathBuf>,
    excluded_file_names: &HashSet<String>,
) -> (HashMap<String, String>, Vec<String>) {
    let mut snapshot = HashMap::new();
    let mut errors = Vec::new();
    walk(
        root,
        excluded_directory_names,
        excluded_files,
        excluded_file_names,
        &mut snapshot,
        &mut errors,
    );
    (snapshot, errors)
}

fn walk(
    dir: &Path,
    excluded_directory_names: &HashSet<String>,
    excluded_files: &HashSet<PathBuf>,
    excluded_file_names: &HashSet<String>,
    snapshot: &mut HashMap<String, String>,
    errors: &mut Vec<String>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                errors.push(e.to_string());
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if excluded_directory_names.contains(&name) {
                continue;
            }
            walk(
                &path,
                excluded_directory_names,
                excluded_files,
                excluded_file_names,
                snapshot,
                errors,
            );
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if excluded_file_names.contains(&name) {
            continue;
        }
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if excluded_files.contains(&canonical) {
            continue;
        }
        match hash_file(&path) {
            Ok(hash) => {
                snapshot.insert(canonical.to_string_lossy().to_string(), hash);
            }
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_snapshot_exclusions() {
        let tmp = std::env::temp_dir().join(format!("sentinel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("keep")).unwrap();
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        std::fs::write(tmp.join("keep").join("a.txt"), "x").unwrap();
        std::fs::write(tmp.join(".git").join("config"), "y").unwrap();

        let (snap, errs) = build_file_snapshot(
            &tmp,
            &HashSet::from([".git".into()]),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(errs.is_empty());
        assert_eq!(snap.len(), 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parses_ss_line() {
        let line = "tcp ESTAB 0 0 127.0.0.1:5555 1.2.3.4:443 users:(\"curl\",pid=1234,fd=3)";
        let conn = parse_ss_line(line).expect("parse failed");
        assert_eq!(conn.remote_address, "1.2.3.4");
        assert_eq!(conn.remote_port, 443);
        assert_eq!(conn.pid, Some(1234));
        assert_eq!(conn.process_name.as_deref(), Some("curl"));
    }
}
