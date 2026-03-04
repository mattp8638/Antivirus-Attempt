use std::time::SystemTime;

use crate::behavioral_analyzer::ProcessEventView;

pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub image_path: String,
    pub command_line: String,
    pub timestamp: SystemTime,
    pub parent_image: Option<String>,
}

impl ProcessEventView for ProcessEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn ppid(&self) -> u32 {
        self.ppid
    }
    fn image_path(&self) -> &str {
        &self.image_path
    }
    fn command_line(&self) -> &str {
        &self.command_line
    }
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
    fn parent_image_path(&self) -> Option<&str> {
        self.parent_image.as_deref()
    }
}
