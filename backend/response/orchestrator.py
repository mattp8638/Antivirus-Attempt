import logging
import uuid
import threading
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import json
from pathlib import Path

from .actions import (
    ActionExecutor, ResponseAction, ActionResult,
    ActionType, ActionStatus
)

logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    """Status of playbook execution."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"


@dataclass
class PlaybookAction:
    """Represents an action within a playbook."""
    action_type: ActionType
    parameters: Dict
    requires_approval: bool = False
    depends_on: List[int] = None  # Indices of actions this depends on
    continue_on_failure: bool = False
    timeout_seconds: int = 300
    
    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []


@dataclass
class Playbook:
    """Defines a sequence of automated response actions."""
    id: str
    name: str
    description: str
    actions: List[PlaybookAction]
    triggered_by: str  # rule_id, manual, etc.
    endpoint_id: str
    alert_id: Optional[str] = None
    parallel: bool = False  # Execute actions in parallel where possible
    auto_approve: bool = False  # Auto-approve all actions
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat() + "Z"


@dataclass
class PlaybookExecution:
    """Tracks execution of a playbook."""
    id: str
    playbook: Playbook
    status: PlaybookStatus
    actions: List[ResponseAction]
    started_at: str
    completed_at: Optional[str] = None
    rollback_performed: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'playbook_id': self.playbook.id,
            'playbook_name': self.playbook.name,
            'status': self.status.value,
            'actions': [a.to_dict() for a in self.actions],
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'rollback_performed': self.rollback_performed,
            'error': self.error
        }


class ResponseOrchestrator:
    """
    Orchestrates automated response actions.
    
    Manages playbook execution, approval workflows, and rollback operations.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize response orchestrator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.executor = ActionExecutor(config)
        self.executions: Dict[str, PlaybookExecution] = {}
        self.approval_queue: List[ResponseAction] = []
        self.approval_callbacks: Dict[str, Callable] = {}  # action_id -> callback
        
        # Load playbook templates
        self.playbook_templates: Dict[str, Playbook] = {}
        self._load_playbook_templates()
        
        logger.info("Response orchestrator initialized")
    
    def _load_playbook_templates(self):
        """
        Load predefined playbook templates.
        """
        # Ransomware Response Playbook
        self.playbook_templates['ransomware_response'] = Playbook(
            id='ransomware_response',
            name='Ransomware Response',
            description='Automated response to ransomware detection',
            actions=[
                PlaybookAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    parameters={'pid': None},  # Will be filled at runtime
                    requires_approval=False,
                    continue_on_failure=True
                ),
                PlaybookAction(
                    action_type=ActionType.ISOLATE_ENDPOINT,
                    parameters={},
                    requires_approval=True,  # Critical action
                    depends_on=[0]
                ),
                PlaybookAction(
                    action_type=ActionType.COLLECT_EVIDENCE,
                    parameters={},
                    requires_approval=False,
                    depends_on=[1]
                ),
            ],
            triggered_by='template',
            endpoint_id='',
            parallel=False
        )
        
        # Malware Containment Playbook
        self.playbook_templates['malware_containment'] = Playbook(
            id='malware_containment',
            name='Malware Containment',
            description='Contain malware execution',
            actions=[
                PlaybookAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    parameters={'pid': None},
                    requires_approval=False
                ),
                PlaybookAction(
                    action_type=ActionType.QUARANTINE_FILE,
                    parameters={'file_path': None},
                    requires_approval=False,
                    depends_on=[0]
                ),
                PlaybookAction(
                    action_type=ActionType.BLOCK_IP,
                    parameters={'ip_address': None},
                    requires_approval=False
                ),
            ],
            triggered_by='template',
            endpoint_id='',
            parallel=False
        )
        
        # Credential Theft Response
        self.playbook_templates['credential_theft_response'] = Playbook(
            id='credential_theft_response',
            name='Credential Theft Response',
            description='Response to credential dumping',
            actions=[
                PlaybookAction(
                    action_type=ActionType.TERMINATE_PROCESS,
                    parameters={'pid': None},
                    requires_approval=False
                ),
                PlaybookAction(
                    action_type=ActionType.ISOLATE_ENDPOINT,
                    parameters={},
                    requires_approval=True,
                    depends_on=[0]
                ),
                PlaybookAction(
                    action_type=ActionType.COLLECT_EVIDENCE,
                    parameters={},
                    requires_approval=False,
                    depends_on=[0]
                ),
            ],
            triggered_by='template',
            endpoint_id='',
            parallel=False
        )
        
        logger.info(f"Loaded {len(self.playbook_templates)} playbook templates")
    
    def execute_playbook(self, playbook: Playbook, async_execution: bool = True) -> PlaybookExecution:
        """
        Execute a response playbook.
        
        Args:
            playbook: Playbook to execute
            async_execution: Execute in background thread
            
        Returns:
            PlaybookExecution tracking object
        """
        execution_id = str(uuid.uuid4())
        
        # Convert playbook actions to ResponseActions
        response_actions = []
        for idx, pb_action in enumerate(playbook.actions):
            action = ResponseAction(
                id=f"{execution_id}_{idx}",
                action_type=pb_action.action_type,
                endpoint_id=playbook.endpoint_id,
                parameters=pb_action.parameters,
                alert_id=playbook.alert_id,
                requires_approval=pb_action.requires_approval,
                initiated_by=playbook.triggered_by,
                status=ActionStatus.PENDING
            )
            response_actions.append(action)
        
        execution = PlaybookExecution(
            id=execution_id,
            playbook=playbook,
            status=PlaybookStatus.RUNNING,
            actions=response_actions,
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        self.executions[execution_id] = execution
        
        logger.info(f"Starting playbook execution {execution_id}: {playbook.name}")
        
        if async_execution:
            # Execute in background thread
            thread = threading.Thread(
                target=self._execute_playbook_thread,
                args=(execution,),
                daemon=True
            )
            thread.start()
        else:
            # Execute synchronously
            self._execute_playbook_thread(execution)
        
        return execution
    
    def _execute_playbook_thread(self, execution: PlaybookExecution):
        """
        Thread worker that executes playbook actions.
        
        Args:
            execution: PlaybookExecution to run
        """
        try:
            playbook = execution.playbook
            completed_indices = set()
            
            # Execute actions respecting dependencies
            for idx, (action, pb_action) in enumerate(zip(execution.actions, playbook.actions)):
                # Check dependencies
                if pb_action.depends_on:
                    # Wait for dependencies to complete
                    while not all(dep_idx in completed_indices for dep_idx in pb_action.depends_on):
                        time.sleep(0.5)
                        
                        # Check if playbook was cancelled
                        if execution.status == PlaybookStatus.CANCELLED:
                            logger.info(f"Playbook {execution.id} cancelled")
                            return
                    
                    # Check if any dependency failed
                    dependency_failed = any(
                        execution.actions[dep_idx].status == ActionStatus.FAILED
                        for dep_idx in pb_action.depends_on
                    )
                    
                    if dependency_failed and not pb_action.continue_on_failure:
                        logger.warning(f"Skipping action {idx} due to failed dependency")
                        action.status = ActionStatus.FAILED
                        action.result = ActionResult(
                            success=False,
                            action_id=action.id,
                            action_type=action.action_type,
                            timestamp=datetime.utcnow().isoformat() + "Z",
                            message="Dependency failed",
                            details={},
                            error="Dependency action failed"
                        )
                        completed_indices.add(idx)
                        continue
                
                # Check if approval required
                if action.requires_approval and not playbook.auto_approve:
                    action.status = ActionStatus.REQUIRES_APPROVAL
                    execution.status = PlaybookStatus.AWAITING_APPROVAL
                    self.approval_queue.append(action)
                    
                    logger.info(f"Action {action.id} awaiting approval")
                    
                    # Wait for approval
                    while action.status == ActionStatus.REQUIRES_APPROVAL:
                        time.sleep(1)
                        
                        # Check if playbook was cancelled
                        if execution.status == PlaybookStatus.CANCELLED:
                            return
                    
                    # Check if rejected
                    if action.status == ActionStatus.REJECTED:
                        logger.info(f"Action {action.id} rejected, stopping playbook")
                        execution.status = PlaybookStatus.FAILED
                        execution.error = "Action rejected by approver"
                        return
                    
                    execution.status = PlaybookStatus.RUNNING
                
                # Execute action
                logger.info(f"Executing action {idx}: {action.action_type.value}")
                result = self.executor.execute(action)
                
                if not result.success:
                    logger.error(f"Action {idx} failed: {result.message}")
                    
                    if not pb_action.continue_on_failure:
                        execution.status = PlaybookStatus.FAILED
                        execution.error = f"Action {idx} failed: {result.message}"
                        execution.completed_at = datetime.utcnow().isoformat() + "Z"
                        return
                
                completed_indices.add(idx)
            
            # All actions completed
            execution.status = PlaybookStatus.COMPLETED
            execution.completed_at = datetime.utcnow().isoformat() + "Z"
            
            logger.info(f"Playbook {execution.id} completed successfully")
            
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}", exc_info=True)
            execution.status = PlaybookStatus.FAILED
            execution.error = str(e)
            execution.completed_at = datetime.utcnow().isoformat() + "Z"
    
    def approve_action(self, action_id: str, approved_by: str) -> bool:
        """
        Approve a pending action.
        
        Args:
            action_id: ID of action to approve
            approved_by: Username of approver
            
        Returns:
            True if approved, False if not found
        """
        # Find action in approval queue
        for action in self.approval_queue:
            if action.id == action_id:
                action.status = ActionStatus.APPROVED
                action.approved_by = approved_by
                self.approval_queue.remove(action)
                
                logger.info(f"Action {action_id} approved by {approved_by}")
                
                # Call callback if registered
                if action_id in self.approval_callbacks:
                    self.approval_callbacks[action_id](True)
                    del self.approval_callbacks[action_id]
                
                return True
        
        return False
    
    def reject_action(self, action_id: str, rejected_by: str, reason: str = "") -> bool:
        """
        Reject a pending action.
        
        Args:
            action_id: ID of action to reject
            rejected_by: Username of rejector
            reason: Reason for rejection
            
        Returns:
            True if rejected, False if not found
        """
        for action in self.approval_queue:
            if action.id == action_id:
                action.status = ActionStatus.REJECTED
                self.approval_queue.remove(action)
                
                logger.info(f"Action {action_id} rejected by {rejected_by}: {reason}")
                
                # Call callback if registered
                if action_id in self.approval_callbacks:
                    self.approval_callbacks[action_id](False)
                    del self.approval_callbacks[action_id]
                
                return True
        
        return False
    
    def cancel_playbook(self, execution_id: str) -> bool:
        """
        Cancel a running playbook.
        
        Args:
            execution_id: ID of playbook execution to cancel
            
        Returns:
            True if cancelled, False if not found
        """
        execution = self.executions.get(execution_id)
        if not execution:
            return False
        
        execution.status = PlaybookStatus.CANCELLED
        logger.info(f"Playbook {execution_id} cancelled")
        
        return True
    
    def rollback_action(self, action_id: str) -> ActionResult:
        """
        Rollback a completed action.
        
        Args:
            action_id: ID of action to rollback
            
        Returns:
            ActionResult of rollback operation
        """
        # Find the action
        action = None
        for execution in self.executions.values():
            for a in execution.actions:
                if a.id == action_id:
                    action = a
                    break
            if action:
                break
        
        if not action or not action.result or not action.result.rollback_info:
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=ActionType.TERMINATE_PROCESS,  # Placeholder
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Action not found or cannot be rolled back",
                details={},
                error="No rollback info available"
            )
        
        logger.info(f"Rolling back action {action_id}")
        
        # Create rollback action
        rollback_action_type = self._get_rollback_action_type(action.action_type)
        if not rollback_action_type:
            return ActionResult(
                success=False,
                action_id=action_id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Action type does not support rollback",
                details={},
                error="Rollback not supported"
            )
        
        rollback_action = ResponseAction(
            id=f"{action_id}_rollback",
            action_type=rollback_action_type,
            endpoint_id=action.endpoint_id,
            parameters=action.result.rollback_info,
            initiated_by="rollback_system"
        )
        
        result = self.executor.execute(rollback_action)
        
        if result.success:
            action.status = ActionStatus.ROLLED_BACK
            logger.info(f"Action {action_id} rolled back successfully")
        
        return result
    
    def _get_rollback_action_type(self, original_type: ActionType) -> Optional[ActionType]:
        """
        Get the rollback action type for an original action.
        
        Args:
            original_type: Original ActionType
            
        Returns:
            Rollback ActionType or None
        """
        rollback_map = {
            ActionType.ISOLATE_ENDPOINT: ActionType.UNISOLATE_ENDPOINT,
            ActionType.QUARANTINE_FILE: ActionType.RESTORE_FILE,
            # Add more mappings as needed
        }
        
        return rollback_map.get(original_type)
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict]:
        """
        Get status of a playbook execution.
        
        Args:
            execution_id: Execution ID
            
        Returns:
            Execution status dictionary or None
        """
        execution = self.executions.get(execution_id)
        if not execution:
            return None
        
        return execution.to_dict()
    
    def get_pending_approvals(self) -> List[Dict]:
        """
        Get list of actions awaiting approval.
        
        Returns:
            List of action dictionaries
        """
        return [action.to_dict() for action in self.approval_queue]
    
    def get_playbook_template(self, template_id: str) -> Optional[Playbook]:
        """
        Get a playbook template by ID.
        
        Args:
            template_id: Template ID
            
        Returns:
            Playbook template or None
        """
        return self.playbook_templates.get(template_id)
    
    def create_playbook_from_template(
        self,
        template_id: str,
        endpoint_id: str,
        parameters: Dict,
        alert_id: Optional[str] = None
    ) -> Optional[Playbook]:
        """
        Create a playbook instance from a template.
        
        Args:
            template_id: ID of template to use
            endpoint_id: Target endpoint
            parameters: Runtime parameters to fill in
            alert_id: Associated alert ID
            
        Returns:
            Playbook instance or None
        """
        template = self.playbook_templates.get(template_id)
        if not template:
            return None
        
        # Clone template
        import copy
        playbook = copy.deepcopy(template)
        
        # Set runtime values
        playbook.id = str(uuid.uuid4())
        playbook.endpoint_id = endpoint_id
        playbook.alert_id = alert_id
        playbook.triggered_by = parameters.get('triggered_by', 'manual')
        
        # Fill in action parameters
        for action in playbook.actions:
            for key, value in action.parameters.items():
                if value is None and key in parameters:
                    action.parameters[key] = parameters[key]
        
        return playbook


def main():
    """CLI interface for response orchestrator."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    config = {
        'quarantine': {
            'directory': '/var/tamsilcms/quarantine'
        },
        'response': {
            'evidence_dir': '/var/tamsilcms/evidence',
            'audit_log': '/var/log/tamsilcms/response_audit.log'
        }
    }
    
    orchestrator = ResponseOrchestrator(config)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python orchestrator.py templates              - List playbook templates")
        print("  python orchestrator.py execute <template_id>  - Execute playbook")
        print("  python orchestrator.py status <execution_id>  - Check execution status")
        print("  python orchestrator.py approvals              - List pending approvals")
        return
    
    command = sys.argv[1]
    
    if command == "templates":
        print("\nAvailable Playbook Templates:\n")
        for template_id, playbook in orchestrator.playbook_templates.items():
            print(f"{template_id}: {playbook.name}")
            print(f"  Description: {playbook.description}")
            print(f"  Actions: {len(playbook.actions)}")
            print()
    
    elif command == "execute" and len(sys.argv) > 2:
        template_id = sys.argv[2]
        
        # Create playbook from template
        playbook = orchestrator.create_playbook_from_template(
            template_id=template_id,
            endpoint_id="test-endpoint",
            parameters={'pid': 1234, 'triggered_by': 'manual'}
        )
        
        if not playbook:
            print(f"Template {template_id} not found")
            return
        
        # Execute
        execution = orchestrator.execute_playbook(playbook, async_execution=False)
        
        print(f"\nExecution {execution.id} completed")
        print(f"Status: {execution.status.value}")
        print(f"Actions executed: {len(execution.actions)}")
    
    elif command == "status" and len(sys.argv) > 2:
        execution_id = sys.argv[2]
        status = orchestrator.get_execution_status(execution_id)
        
        if status:
            print(json.dumps(status, indent=2))
        else:
            print(f"Execution {execution_id} not found")
    
    elif command == "approvals":
        approvals = orchestrator.get_pending_approvals()
        print(f"\nPending Approvals: {len(approvals)}\n")
        for action in approvals:
            print(f"Action {action['id']}:")
            print(f"  Type: {action['action_type']}")
            print(f"  Endpoint: {action['endpoint_id']}")
            print()
    
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()
