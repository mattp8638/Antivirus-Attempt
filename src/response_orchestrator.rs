//! Response Orchestration
//! Coordinates execution of multi-action playbooks

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use log::{error, info, warn};
use uuid::Uuid;

use crate::response::{
    ActionExecutor, ActionType, ActionStatus, ResponseAction, ResponseConfig
};

/// Status of playbook execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    AwaitingApproval,
}

/// Action within a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub action_type: ActionType,
    pub parameters: HashMap<String, serde_json::Value>,
    pub requires_approval: bool,
    pub depends_on: Vec<usize>,
    pub continue_on_failure: bool,
    pub timeout_seconds: u64,
}

impl PlaybookAction {
    pub fn new(action_type: ActionType) -> Self {
        Self {
            action_type,
            parameters: HashMap::new(),
            requires_approval: false,
            depends_on: Vec::new(),
            continue_on_failure: false,
            timeout_seconds: 300,
        }
    }
    
    pub fn with_param(mut self, key: &str, value: serde_json::Value) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }
    
    pub fn requires_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }
    
    pub fn depends_on(mut self, indices: Vec<usize>) -> Self {
        self.depends_on = indices;
        self
    }
}

/// Playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub actions: Vec<PlaybookAction>,
    pub triggered_by: String,
    pub endpoint_id: String,
    pub alert_id: Option<String>,
    pub parallel: bool,
    pub auto_approve: bool,
}

impl Playbook {
    pub fn new(name: &str, endpoint_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            actions: Vec::new(),
            triggered_by: "manual".to_string(),
            endpoint_id: endpoint_id.to_string(),
            alert_id: None,
            parallel: false,
            auto_approve: false,
        }
    }
    
    pub fn add_action(mut self, action: PlaybookAction) -> Self {
        self.actions.push(action);
        self
    }
    
    pub fn with_alert(mut self, alert_id: &str) -> Self {
        self.alert_id = Some(alert_id.to_string());
        self
    }
}

/// Playbook execution tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub id: String,
    pub playbook_id: String,
    pub playbook_name: String,
    pub status: PlaybookStatus,
    pub actions: Vec<ResponseAction>,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
    pub rollback_performed: bool,
    pub error: Option<String>,
}

/// Response orchestrator
pub struct ResponseOrchestrator {
    executor: Arc<ActionExecutor>,
    executions: Arc<Mutex<HashMap<String, PlaybookExecution>>>,
    approval_queue: Arc<Mutex<Vec<String>>>, // action IDs awaiting approval
    playbook_templates: HashMap<String, Playbook>,
}

impl ResponseOrchestrator {
    /// Create new orchestrator
    pub fn new(config: ResponseConfig) -> Result<Self> {
        let executor = Arc::new(ActionExecutor::new(config)?);
        let mut templates = HashMap::new();
        
        // Load predefined playbooks
        templates.insert(
            "ransomware_response".to_string(),
            Self::ransomware_response_playbook(),
        );
        templates.insert(
            "malware_containment".to_string(),
            Self::malware_containment_playbook(),
        );
        templates.insert(
            "credential_theft_response".to_string(),
            Self::credential_theft_playbook(),
        );
        
        info!("Response orchestrator initialized with {} playbook templates", templates.len());
        
        Ok(Self {
            executor,
            executions: Arc::new(Mutex::new(HashMap::new())),
            approval_queue: Arc::new(Mutex::new(Vec::new())),
            playbook_templates: templates,
        })
    }
    
    /// Ransomware response playbook
    fn ransomware_response_playbook() -> Playbook {
        Playbook::new("Ransomware Response", "")
            .add_action(
                PlaybookAction::new(ActionType::TerminateProcess)
                    .with_param("pid", serde_json::json!(0)) // Will be filled at runtime
            )
            .add_action(
                PlaybookAction::new(ActionType::IsolateEndpoint)
                    .requires_approval()
                    .depends_on(vec![0])
            )
            .add_action(
                PlaybookAction::new(ActionType::CollectEvidence)
                    .depends_on(vec![1])
            )
    }
    
    /// Malware containment playbook
    fn malware_containment_playbook() -> Playbook {
        Playbook::new("Malware Containment", "")
            .add_action(
                PlaybookAction::new(ActionType::TerminateProcess)
            )
            .add_action(
                PlaybookAction::new(ActionType::QuarantineFile)
                    .depends_on(vec![0])
            )
            .add_action(
                PlaybookAction::new(ActionType::BlockIp)
            )
    }
    
    /// Credential theft response playbook
    fn credential_theft_playbook() -> Playbook {
        Playbook::new("Credential Theft Response", "")
            .add_action(
                PlaybookAction::new(ActionType::TerminateProcess)
            )
            .add_action(
                PlaybookAction::new(ActionType::IsolateEndpoint)
                    .requires_approval()
                    .depends_on(vec![0])
            )
            .add_action(
                PlaybookAction::new(ActionType::CollectEvidence)
                    .depends_on(vec![0])
            )
    }
    
    /// Execute a playbook
    pub fn execute_playbook(&self, playbook: Playbook) -> Result<String> {
        let execution_id = Uuid::new_v4().to_string();
        
        // Convert playbook actions to response actions
        let mut response_actions = Vec::new();
        for (idx, pb_action) in playbook.actions.iter().enumerate() {
            let action = ResponseAction {
                id: format!("{}_{}", execution_id, idx),
                action_type: pb_action.action_type.clone(),
                endpoint_id: playbook.endpoint_id.clone(),
                parameters: pb_action.parameters.clone(),
                alert_id: playbook.alert_id.clone(),
                rule_id: None,
                initiated_by: playbook.triggered_by.clone(),
                requires_approval: pb_action.requires_approval,
                status: ActionStatus::Pending,
                created_at: SystemTime::now(),
                executed_at: None,
                completed_at: None,
            };
            response_actions.push(action);
        }
        
        let execution = PlaybookExecution {
            id: execution_id.clone(),
            playbook_id: playbook.id.clone(),
            playbook_name: playbook.name.clone(),
            status: PlaybookStatus::Running,
            actions: response_actions,
            started_at: SystemTime::now(),
            completed_at: None,
            rollback_performed: false,
            error: None,
        };
        
        // Store execution
        {
            let mut executions = self.executions.lock().unwrap();
            executions.insert(execution_id.clone(), execution);
        }
        
        info!("Started playbook execution {}: {}", execution_id, playbook.name);
        
        // Execute in background
        let executor = Arc::clone(&self.executor);
        let executions = Arc::clone(&self.executions);
        let approval_queue = Arc::clone(&self.approval_queue);
        
        let execution_id_clone = execution_id.clone();
        tokio::spawn(async move {
            Self::execute_playbook_thread(
            execution_id_clone,
                playbook,
                executor,
                executions,
                approval_queue,
            ).await;
        });
        
        Ok(execution_id)
    }
    
    /// Background execution thread
    async fn execute_playbook_thread(
        execution_id: String,
        playbook: Playbook,
        executor: Arc<ActionExecutor>,
        executions: Arc<Mutex<HashMap<String, PlaybookExecution>>>,
        approval_queue: Arc<Mutex<Vec<String>>>,
    ) {
        let mut completed_indices = std::collections::HashSet::new();
        
        // Get mutable reference to execution
        let action_count = {
            let executions_guard = executions.lock().unwrap();
            let execution = executions_guard.get(&execution_id).unwrap();
            execution.actions.len()
        };
        
        for idx in 0..action_count {
            // Check dependencies
            let depends_on = playbook.actions[idx].depends_on.clone();
            if !depends_on.is_empty() {
                // Wait for dependencies
                loop {
                    if depends_on.iter().all(|dep_idx| completed_indices.contains(dep_idx)) {
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            }
            
            // Get action
            let mut action = {
                let mut executions_guard = executions.lock().unwrap();
                let execution = executions_guard.get_mut(&execution_id).unwrap();
                execution.actions[idx].clone()
            };
            
            // Check if requires approval
            if action.requires_approval && !playbook.auto_approve {
                action.status = ActionStatus::RequiresApproval;
                
                // Add to approval queue
                {
                    let mut queue = approval_queue.lock().unwrap();
                    queue.push(action.id.clone());
                }
                
                info!("Action {} awaiting approval", action.id);
                
                // Wait for approval
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    
                    let executions_guard = executions.lock().unwrap();
                    let execution = executions_guard.get(&execution_id).unwrap();
                    let current_status = execution.actions[idx].status.clone();
                    
                    if current_status == ActionStatus::Approved {
                        break;
                    } else if current_status == ActionStatus::Rejected {
                        error!("Action {} rejected, stopping playbook", action.id);
                        return;
                    }
                }
            }
            
            // Execute action
            info!("Executing action {}: {:?}", idx, action.action_type);
            
            let result = executor.execute(&mut action);
            
            // Update execution
            {
                let mut executions_guard = executions.lock().unwrap();
                let execution = executions_guard.get_mut(&execution_id).unwrap();
                execution.actions[idx] = action.clone();
                
                if let Err(e) = result {
                    error!("Action {} failed: {}", idx, e);
                    if !playbook.actions[idx].continue_on_failure {
                        execution.status = PlaybookStatus::Failed;
                        execution.error = Some(e.to_string());
                        execution.completed_at = Some(SystemTime::now());
                        return;
                    }
                }
            }
            
            completed_indices.insert(idx);
        }
        
        // Mark execution as completed
        {
            let mut executions_guard = executions.lock().unwrap();
            if let Some(execution) = executions_guard.get_mut(&execution_id) {
                execution.status = PlaybookStatus::Completed;
                execution.completed_at = Some(SystemTime::now());
            }
        }
        
        info!("Playbook execution {} completed", execution_id);
    }
    
    /// Approve an action
    pub fn approve_action(&self, action_id: &str, approved_by: &str) -> Result<()> {
        let mut executions = self.executions.lock().unwrap();
        
        for execution in executions.values_mut() {
            for action in &mut execution.actions {
                if action.id == action_id && action.status == ActionStatus::RequiresApproval {
                    action.status = ActionStatus::Approved;
                    info!("Action {} approved by {}", action_id, approved_by);
                    
                    // Remove from approval queue
                    let mut queue = self.approval_queue.lock().unwrap();
                    queue.retain(|id| id != action_id);
                    
                    return Ok(());
                }
            }
        }
        
        anyhow::bail!("Action not found or not awaiting approval")
    }
    
    /// Reject an action
    pub fn reject_action(&self, action_id: &str, rejected_by: &str, reason: &str) -> Result<()> {
        let mut executions = self.executions.lock().unwrap();
        
        for execution in executions.values_mut() {
            for action in &mut execution.actions {
                if action.id == action_id && action.status == ActionStatus::RequiresApproval {
                    action.status = ActionStatus::Rejected;
                    warn!("Action {} rejected by {}: {}", action_id, rejected_by, reason);
                    
                    // Remove from approval queue
                    let mut queue = self.approval_queue.lock().unwrap();
                    queue.retain(|id| id != action_id);
                    
                    return Ok(());
                }
            }
        }
        
        anyhow::bail!("Action not found or not awaiting approval")
    }
    
    /// Get execution status
    pub fn get_execution_status(&self, execution_id: &str) -> Option<PlaybookExecution> {
        let executions = self.executions.lock().unwrap();
        executions.get(execution_id).cloned()
    }
    
    /// Get pending approvals
    pub fn get_pending_approvals(&self) -> Vec<String> {
        let queue = self.approval_queue.lock().unwrap();
        queue.clone()
    }
    
    /// Get playbook template
    pub fn get_template(&self, template_id: &str) -> Option<Playbook> {
        self.playbook_templates.get(template_id).cloned()
    }
    
    /// Create playbook from template
    pub fn create_from_template(
        &self,
        template_id: &str,
        endpoint_id: &str,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<Playbook> {
        let mut playbook = self.get_template(template_id)
            .context("Template not found")?;
        
        playbook.endpoint_id = endpoint_id.to_string();
        
        // Fill in parameters
        for action in &mut playbook.actions {
            for (key, value) in &parameters {
                if let Some(param) = action.parameters.get_mut(key) {
                    if param.is_null() {
                        *param = value.clone();
                    }
                }
            }
        }
        
        Ok(playbook)
    }
}
