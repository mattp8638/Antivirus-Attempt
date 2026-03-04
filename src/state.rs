use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AgentState {
    pub file_hashes: HashMap<String, String>,
    pub kernel_cursor_unix: u64,
    pub windows_cursor_unix: u64,
    pub memory_cursor_unix: u64,
    pub ransomware_last_alert_ts: u64,
    pub yara_last_fetch_ts: u64,
}

impl AgentState {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                file_hashes: HashMap::new(),
                kernel_cursor_unix: 0,
                windows_cursor_unix: 0,
                memory_cursor_unix: 0,
                ransomware_last_alert_ts: 0,
                yara_last_fetch_ts: 0,
            });
        }
        let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut file_hashes = HashMap::new();
        let mut kernel_cursor_unix = 0;
        let mut windows_cursor_unix = 0;
        let mut memory_cursor_unix = 0;
        let mut ransomware_last_alert_ts = 0;
        let mut yara_last_fetch_ts = 0;
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("#kernel_cursor\t") {
                kernel_cursor_unix = value.parse::<u64>().unwrap_or(0);
                continue;
            }
            if let Some(value) = line.strip_prefix("#windows_cursor\t") {
                windows_cursor_unix = value.parse::<u64>().unwrap_or(0);
                continue;
            }
            if let Some(value) = line.strip_prefix("#memory_cursor\t") {
                memory_cursor_unix = value.parse::<u64>().unwrap_or(0);
                continue;
            }
            if let Some(value) = line.strip_prefix("#ransomware_alert_ts\t") {
                ransomware_last_alert_ts = value.parse::<u64>().unwrap_or(0);
                continue;
            }
            if let Some(value) = line.strip_prefix("#yara_rules_ts\t") {
                yara_last_fetch_ts = value.parse::<u64>().unwrap_or(0);
                continue;
            }
            let mut parts = line.splitn(2, '\t');
            if let (Some(path), Some(hash)) = (parts.next(), parts.next()) {
                file_hashes.insert(path.to_string(), hash.to_string());
            }
        }
        Ok(Self {
            file_hashes,
            kernel_cursor_unix,
            windows_cursor_unix,
            memory_cursor_unix,
            ransomware_last_alert_ts,
            yara_last_fetch_ts,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut data = String::new();
        data.push_str("#kernel_cursor\t");
        data.push_str(&self.kernel_cursor_unix.to_string());
        data.push('\n');
        data.push_str("#windows_cursor\t");
        data.push_str(&self.windows_cursor_unix.to_string());
        data.push('\n');
        data.push_str("#memory_cursor\t");
        data.push_str(&self.memory_cursor_unix.to_string());
        data.push('\n');
        data.push_str("#ransomware_alert_ts\t");
        data.push_str(&self.ransomware_last_alert_ts.to_string());
        data.push('\n');
        data.push_str("#yara_rules_ts\t");
        data.push_str(&self.yara_last_fetch_ts.to_string());
        data.push('\n');
        for (k, v) in &self.file_hashes {
            data.push_str(k);
            data.push('\t');
            data.push_str(v);
            data.push('\n');
        }
        fs::write(path, data).map_err(|e| e.to_string())
    }
}
