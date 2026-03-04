use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub pid: Option<i32>,
    pub attack_tactic: Option<String>,
    pub attack_technique: Option<String>,
    pub intel_tags: Vec<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub incident_id: String,
    pub primary_pid: i32,
    pub risk_score: u32,
    pub alert_count: usize,
    pub summary: String,
}

impl Alert {
    pub fn new(rule: &str, severity: &str, message: String) -> Self {
        Self {
            rule: rule.to_string(),
            severity: severity.to_string(),
            message,
            pid: None,
            attack_tactic: None,
            attack_technique: None,
            intel_tags: Vec::new(),
            details: None,
        }
    }

    pub fn with_pid(rule: &str, severity: &str, message: String, pid: i32) -> Self {
        Self {
            rule: rule.to_string(),
            severity: severity.to_string(),
            message,
            pid: Some(pid),
            attack_tactic: None,
            attack_technique: None,
            intel_tags: Vec::new(),
            details: None,
        }
    }

    pub fn serialize(&self) -> String {
        let mut suffix_parts = Vec::new();
        if let Some(tactic) = &self.attack_tactic {
            suffix_parts.push(format!("tactic={}", tactic));
        }
        if let Some(technique) = &self.attack_technique {
            suffix_parts.push(format!("technique={}", technique));
        }
        if !self.intel_tags.is_empty() {
            suffix_parts.push(format!("tags={}", self.intel_tags.join(",")));
        }
        if let Some(details) = &self.details {
            if let Ok(serialized) = serde_json::to_string(details) {
                suffix_parts.push(format!("details={}", serialized));
            }
        }
        let suffix = if suffix_parts.is_empty() {
            String::new()
        } else {
            format!(" [{}]", suffix_parts.join(" "))
        };
        format!(
            "[{}] {}: {}{}",
            self.severity, self.rule, self.message, suffix
        )
    }

    pub fn severity_weight(&self) -> u32 {
        match self.severity.as_str() {
            "critical" => 10,
            "high" => 7,
            "medium" => 4,
            "low" => 1,
            _ => 0,
        }
    }

    pub fn set_attack(&mut self, tactic: &str, technique: &str) {
        self.attack_tactic = Some(tactic.to_string());
        self.attack_technique = Some(technique.to_string());
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.intel_tags.iter().any(|t| t == tag) {
            self.intel_tags.push(tag.to_string());
        }
    }

    pub fn set_details(&mut self, details: Value) {
        self.details = Some(details);
    }
}

impl Incident {
    pub fn to_json_line(&self, ts_unix: u64) -> String {
        format!(
            "{{\"ts\":{},\"incident_id\":\"{}\",\"pid\":{},\"risk_score\":{},\"alert_count\":{},\"summary\":\"{}\"}}",
            ts_unix,
            escape_json(&self.incident_id),
            self.primary_pid,
            self.risk_score,
            self.alert_count,
            escape_json(&self.summary)
        )
    }
}

pub(crate) fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
