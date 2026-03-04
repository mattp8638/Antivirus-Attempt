use std::time::SystemTime;

use crate::memory_analyzer::{
    InjectionEventView, InjectionTechniqueHint, LsassAccessEventView, MemProtEventView,
};

pub struct InjectionEvent {
    pub source_pid: u32,
    pub source_image: String,
    pub target_pid: u32,
    pub target_image: String,
    pub technique_hint: InjectionTechniqueHint,
    pub timestamp: SystemTime,
}

pub struct MemProtEvent {
    pub pid: u32,
    pub process_image: String,
    pub address: u64,
    pub size: u64,
    pub old_protection: u32,
    pub new_protection: u32,
    pub timestamp: SystemTime,
}

pub struct LsassAccessEvent {
    pub source_pid: u32,
    pub source_image: String,
    pub access_mask: u32,
    pub timestamp: SystemTime,
}

impl InjectionEventView for InjectionEvent {
    fn source_pid(&self) -> u32 {
        self.source_pid
    }
    fn source_image(&self) -> &str {
        &self.source_image
    }
    fn target_pid(&self) -> u32 {
        self.target_pid
    }
    fn target_image(&self) -> &str {
        &self.target_image
    }
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
    fn technique_hint(&self) -> InjectionTechniqueHint {
        self.technique_hint
    }
}

impl MemProtEventView for MemProtEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn process_image(&self) -> &str {
        &self.process_image
    }
    fn address(&self) -> u64 {
        self.address
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn old_protection(&self) -> u32 {
        self.old_protection
    }
    fn new_protection(&self) -> u32 {
        self.new_protection
    }
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
}

impl LsassAccessEventView for LsassAccessEvent {
    fn source_pid(&self) -> u32 {
        self.source_pid
    }
    fn source_image(&self) -> &str {
        &self.source_image
    }
    fn access_mask(&self) -> u32 {
        self.access_mask
    }
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
}
