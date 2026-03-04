import logging
import json
import psutil
import subprocess
import shutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    """Types of response actions."""
    TERMINATE_PROCESS = "terminate_process"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    LOCK_USER = "lock_user"
    STOP_SERVICE = "stop_service"
    START_SERVICE = "start_service"
    RESTORE_FILE = "restore_file"
    UNISOLATE_ENDPOINT = "unisolate_endpoint"
    KILL_NETWORK = "kill_network"
    ENABLE_FIREWALL = "enable_firewall"
    DISABLE_FIREWALL = "disable_firewall"
    MODIFY_REGISTRY = "modify_registry"
    DELETE_FILE = "delete_file"
    COLLECT_EVIDENCE = "collect_evidence"


class ActionStatus(str, Enum):
    """Status of response action."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REQUIRES_APPROVAL = "requires_approval"
    REJECTED = "rejected"


@dataclass
class ActionResult:
    """Result of executing a response action."""
    success: bool
    action_id: str
    action_type: ActionType
    timestamp: str
    message: str
    details: Dict[str, Any]
    rollback_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ResponseAction:
    """Represents a response action to be executed."""
    id: str
    action_type: ActionType
    endpoint_id: str
    parameters: Dict[str, Any]
    alert_id: Optional[str] = None
    rule_id: Optional[str] = None
    initiated_by: str = "system"
    requires_approval: bool = False
    approved_by: Optional[str] = None
    status: ActionStatus = ActionStatus.PENDING
    created_at: str = None
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[ActionResult] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        data = asdict(self)
        # Convert enums to strings
        data['action_type'] = self.action_type.value
        data['status'] = self.status.value
        return data


class ActionExecutor:
    """
    Executes response actions on endpoints.
    
    Handles platform-specific implementation of each action type
    with proper error handling and rollback support.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize action executor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.quarantine_dir = Path(config.get('quarantine', {}).get('directory', 
                                                                     '/var/tamsilcms/quarantine'))
        self.evidence_dir = Path(config.get('response', {}).get('evidence_dir',
                                                                  '/var/tamsilcms/evidence'))
        self.audit_log = Path(config.get('response', {}).get('audit_log',
                                                              '/var/log/tamsilcms/response_audit.log'))
        
        # Create directories
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("Action executor initialized")
    
    def execute(self, action: ResponseAction) -> ActionResult:
        """
        Execute a response action.
        
        Args:
            action: ResponseAction to execute
            
        Returns:
            ActionResult with execution details
        """
        action.status = ActionStatus.IN_PROGRESS
        action.executed_at = datetime.utcnow().isoformat() + "Z"
        
        logger.info(f"Executing action {action.id}: {action.action_type.value}")
        self._audit_log(action, "started")
        
        try:
            # Route to appropriate handler
            if action.action_type == ActionType.TERMINATE_PROCESS:
                result = self._terminate_process(action)
            elif action.action_type == ActionType.ISOLATE_ENDPOINT:
                result = self._isolate_endpoint(action)
            elif action.action_type == ActionType.QUARANTINE_FILE:
                result = self._quarantine_file(action)
            elif action.action_type == ActionType.BLOCK_IP:
                result = self._block_ip(action)
            elif action.action_type == ActionType.BLOCK_DOMAIN:
                result = self._block_domain(action)
            elif action.action_type == ActionType.LOCK_USER:
                result = self._lock_user(action)
            elif action.action_type == ActionType.STOP_SERVICE:
                result = self._stop_service(action)
            elif action.action_type == ActionType.START_SERVICE:
                result = self._start_service(action)
            elif action.action_type == ActionType.RESTORE_FILE:
                result = self._restore_file(action)
            elif action.action_type == ActionType.UNISOLATE_ENDPOINT:
                result = self._unisolate_endpoint(action)
            elif action.action_type == ActionType.DELETE_FILE:
                result = self._delete_file(action)
            elif action.action_type == ActionType.COLLECT_EVIDENCE:
                result = self._collect_evidence(action)
            else:
                result = ActionResult(
                    success=False,
                    action_id=action.id,
                    action_type=action.action_type,
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    message=f"Unknown action type: {action.action_type}",
                    details={},
                    error="Unknown action type"
                )
            
            # Update action status
            if result.success:
                action.status = ActionStatus.COMPLETED
            else:
                action.status = ActionStatus.FAILED
            
            action.completed_at = datetime.utcnow().isoformat() + "Z"
            action.result = result
            
            self._audit_log(action, "completed" if result.success else "failed")
            
            return result
            
        except Exception as e:
            logger.error(f"Action execution failed: {e}", exc_info=True)
            
            result = ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Execution failed: {str(e)}",
                details={},
                error=str(e)
            )
            
            action.status = ActionStatus.FAILED
            action.result = result
            self._audit_log(action, "failed")
            
            return result
    
    def _terminate_process(self, action: ResponseAction) -> ActionResult:
        """
        Terminate a process by PID.
        
        Args:
            action: Action with 'pid' parameter
            
        Returns:
            ActionResult
        """
        pid = action.parameters.get('pid')
        if not pid:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing required parameter: pid",
                details={},
                error="Missing pid parameter"
            )
        
        try:
            process = psutil.Process(pid)
            process_info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline())
            }
            
            # Terminate process
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                # Force kill if not terminated
                process.kill()
                process.wait(timeout=5)
            
            return ActionResult(
                success=True,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Process {pid} terminated successfully",
                details={'process_info': process_info},
                rollback_info=None  # Cannot rollback process termination
            )
            
        except psutil.NoSuchProcess:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Process {pid} not found",
                details={'pid': pid},
                error="Process not found"
            )
        except psutil.AccessDenied:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Access denied to terminate process {pid}",
                details={'pid': pid},
                error="Access denied"
            )
    
    def _isolate_endpoint(self, action: ResponseAction) -> ActionResult:
        """
        Isolate endpoint by disabling network interfaces.
        
        Args:
            action: Action with optional 'exclude_interfaces' parameter
            
        Returns:
            ActionResult
        """
        import platform
        
        exclude = action.parameters.get('exclude_interfaces', [])
        isolated_interfaces = []
        
        try:
            if platform.system() == 'Windows':
                # Windows: Disable network adapters
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Disable-NetAdapter -Confirm:$false'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise Exception(f"Failed to disable adapters: {result.stderr}")
                
                isolated_interfaces.append('all')
                
            elif platform.system() == 'Linux':
                # Linux: Bring down interfaces
                interfaces = psutil.net_if_stats()
                for iface in interfaces:
                    if iface not in exclude and iface != 'lo':
                        subprocess.run(['ip', 'link', 'set', iface, 'down'], 
                                     check=True, timeout=10)
                        isolated_interfaces.append(iface)
            
            else:
                raise Exception(f"Unsupported platform: {platform.system()}")
            
            return ActionResult(
                success=True,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Endpoint isolated: disabled {len(isolated_interfaces)} interfaces",
                details={'isolated_interfaces': isolated_interfaces},
                rollback_info={'interfaces': isolated_interfaces}
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Failed to isolate endpoint: {str(e)}",
                details={},
                error=str(e)
            )
    
    def _quarantine_file(self, action: ResponseAction) -> ActionResult:
        """
        Quarantine a file by moving it to quarantine directory.
        
        Args:
            action: Action with 'file_path' parameter
            
        Returns:
            ActionResult
        """
        file_path = action.parameters.get('file_path')
        if not file_path:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing required parameter: file_path",
                details={},
                error="Missing file_path parameter"
            )
        
        source_path = Path(file_path)
        if not source_path.exists():
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"File not found: {file_path}",
                details={'file_path': file_path},
                error="File not found"
            )
        
        try:
            # Generate quarantine filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            quarantine_filename = f"{timestamp}_{source_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_filename
            
            # Move file to quarantine
            shutil.move(str(source_path), str(quarantine_path))
            
            # Create manifest
            manifest = {
                'original_path': str(source_path),
                'quarantine_path': str(quarantine_path),
                'quarantined_at': datetime.utcnow().isoformat() + "Z",
                'action_id': action.id,
                'reason': action.parameters.get('reason', 'Malicious file detected')
            }
            
            manifest_path = quarantine_path.with_suffix('.json')
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            return ActionResult(
                success=True,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"File quarantined: {file_path}",
                details={
                    'original_path': str(source_path),
                    'quarantine_path': str(quarantine_path)
                },
                rollback_info={
                    'original_path': str(source_path),
                    'quarantine_path': str(quarantine_path)
                }
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Failed to quarantine file: {str(e)}",
                details={'file_path': file_path},
                error=str(e)
            )
    
    def _block_ip(self, action: ResponseAction) -> ActionResult:
        """
        Block an IP address using firewall rules.
        
        Args:
            action: Action with 'ip_address' parameter
            
        Returns:
            ActionResult
        """
        ip_address = action.parameters.get('ip_address')
        if not ip_address:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing required parameter: ip_address",
                details={},
                error="Missing ip_address parameter"
            )
        
        try:
            import platform
            
            if platform.system() == 'Windows':
                # Windows Firewall
                rule_name = f"TamsilCMS_Block_{ip_address}"
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    'dir=out',
                    'action=block',
                    f'remoteip={ip_address}'
                ]
                subprocess.run(cmd, check=True, timeout=30)
                
            elif platform.system() == 'Linux':
                # iptables
                subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip_address, '-j', 'DROP'],
                             check=True, timeout=10)
            
            return ActionResult(
                success=True,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"IP address blocked: {ip_address}",
                details={'ip_address': ip_address},
                rollback_info={'ip_address': ip_address}
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Failed to block IP: {str(e)}",
                details={'ip_address': ip_address},
                error=str(e)
            )
    
    def _block_domain(self, action: ResponseAction) -> ActionResult:
        """
        Block a domain by adding to hosts file.
        
        Args:
            action: Action with 'domain' parameter
            
        Returns:
            ActionResult
        """
        domain = action.parameters.get('domain')
        if not domain:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing required parameter: domain",
                details={},
                error="Missing domain parameter"
            )
        
        try:
            import platform
            
            if platform.system() == 'Windows':
                hosts_path = Path('C:/Windows/System32/drivers/etc/hosts')
            else:
                hosts_path = Path('/etc/hosts')
            
            # Add domain to hosts file
            block_entry = f"127.0.0.1 {domain}  # TamsilCMS Block\n"
            
            with open(hosts_path, 'a') as f:
                f.write(block_entry)
            
            return ActionResult(
                success=True,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Domain blocked: {domain}",
                details={'domain': domain},
                rollback_info={'domain': domain, 'hosts_path': str(hosts_path)}
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message=f"Failed to block domain: {str(e)}",
                details={'domain': domain},
                error=str(e)
            )
    
    def _lock_user(self, action: ResponseAction) -> ActionResult:
        """Lock a user account."""
        # Implementation placeholder
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message="User lock not yet implemented",
            details={}
        )
    
    def _stop_service(self, action: ResponseAction) -> ActionResult:
        """Stop a Windows service."""
        # Implementation placeholder
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message="Service stop not yet implemented",
            details={}
        )
    
    def _start_service(self, action: ResponseAction) -> ActionResult:
        """Start a Windows service."""
        # Implementation placeholder
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message="Service start not yet implemented",
            details={}
        )
    
    def _restore_file(self, action: ResponseAction) -> ActionResult:
        """Restore a quarantined file."""
        quarantine_path = action.parameters.get('quarantine_path')
        if not quarantine_path:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing quarantine_path",
                details={},
                error="Missing parameter"
            )
        
        # Read manifest
        manifest_path = Path(quarantine_path).with_suffix('.json')
        if not manifest_path.exists():
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Manifest not found",
                details={},
                error="Manifest missing"
            )
        
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        original_path = Path(manifest['original_path'])
        quarantine_file = Path(quarantine_path)
        
        # Restore file
        shutil.move(str(quarantine_file), str(original_path))
        manifest_path.unlink()  # Remove manifest
        
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message=f"File restored to {original_path}",
            details={'restored_path': str(original_path)}
        )
    
    def _unisolate_endpoint(self, action: ResponseAction) -> ActionResult:
        """Un-isolate endpoint by re-enabling network."""
        # Implementation would reverse isolation
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message="Endpoint unisolation not yet implemented",
            details={}
        )
    
    def _delete_file(self, action: ResponseAction) -> ActionResult:
        """Delete a file from disk."""
        file_path = action.parameters.get('file_path')
        if not file_path:
            return ActionResult(
                success=False,
                action_id=action.id,
                action_type=action.action_type,
                timestamp=datetime.utcnow().isoformat() + "Z",
                message="Missing file_path",
                details={},
                error="Missing parameter"
            )
        
        Path(file_path).unlink()
        
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message=f"File deleted: {file_path}",
            details={'deleted_path': file_path}
        )
    
    def _collect_evidence(self, action: ResponseAction) -> ActionResult:
        """Collect evidence from endpoint."""
        # Collect memory dump, process list, network connections, etc.
        return ActionResult(
            success=True,
            action_id=action.id,
            action_type=action.action_type,
            timestamp=datetime.utcnow().isoformat() + "Z",
            message="Evidence collection not yet implemented",
            details={}
        )
    
    def _audit_log(self, action: ResponseAction, event: str):
        """
        Write to audit log.
        
        Args:
            action: ResponseAction being logged
            event: Event type (started, completed, failed)
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'event': event,
            'action_id': action.id,
            'action_type': action.action_type.value,
            'endpoint_id': action.endpoint_id,
            'initiated_by': action.initiated_by,
            'status': action.status.value,
            'parameters': action.parameters
        }
        
        with open(self.audit_log, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
