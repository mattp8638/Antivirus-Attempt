"""
Threat Intelligence Feed Synchronization
Synchronizes IOC feeds from TamsilCMS backend.

Features:
- Periodic polling of backend API
- Support for multiple feed formats (STIX, JSON, CSV)
- Atomic feed updates with validation
- TTL-based IOC expiration
- Resilient error handling
"""

import json
import logging
import time
import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


class FeedSyncManager:
    """
    Manages synchronization of threat intelligence feeds from backend.
    
    Handles polling, download, validation, and atomic replacement of
    IOC feeds.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize feed sync manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.feed_url = config.get('threat_intel', {}).get('feed_url', 
                                                            'https://backend.tamsilcms.local/api/intel/iocs')
        self.feed_path = Path(config.get('threat_intel', {}).get('feed_path',
                                                                   '/var/tamsilcms/intel/iocs.json'))
        self.sync_interval = config.get('threat_intel', {}).get('sync_interval_minutes', 60)
        self.auth_token = config.get('threat_intel', {}).get('auth_token', '')
        self.verify_ssl = config.get('threat_intel', {}).get('verify_ssl', True)
        self.timeout = config.get('threat_intel', {}).get('timeout_seconds', 30)
        
        self.last_sync_time: Optional[datetime] = None
        self.last_sync_success = False
        self.sync_thread: Optional[threading.Thread] = None
        self.running = False
        
        # Create feed directory if it doesn't exist
        self.feed_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Feed sync manager initialized (URL: {self.feed_url}, interval: {self.sync_interval}min)")
    
    def start_sync_loop(self):
        """
        Start the background feed synchronization loop.
        """
        if self.running:
            logger.warning("Sync loop already running")
            return
        
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        logger.info("Feed sync loop started")
    
    def stop_sync_loop(self):
        """
        Stop the background synchronization loop.
        """
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        logger.info("Feed sync loop stopped")
    
    def _sync_loop(self):
        """
        Background loop that periodically syncs feeds.
        """
        # Initial sync on startup
        self.sync_feeds()
        
        while self.running:
            try:
                # Calculate time until next sync
                if self.last_sync_time:
                    next_sync = self.last_sync_time + timedelta(minutes=self.sync_interval)
                    wait_seconds = (next_sync - datetime.utcnow()).total_seconds()
                    
                    if wait_seconds > 0:
                        # Sleep in small increments to allow clean shutdown
                        for _ in range(int(wait_seconds)):
                            if not self.running:
                                break
                            time.sleep(1)
                
                if self.running:
                    self.sync_feeds()
                    
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def sync_feeds(self) -> bool:
        """
        Synchronize IOC feeds from backend.
        
        Returns:
            True if sync was successful, False otherwise
        """
        logger.info("Starting feed synchronization...")
        
        try:
            # Download feed from backend
            feed_data = self._download_feed()
            
            if not feed_data:
                logger.error("Failed to download feed")
                self.last_sync_success = False
                self.last_sync_time = datetime.utcnow()
                return False
            
            # Validate feed format
            if not self._validate_feed(feed_data):
                logger.error("Feed validation failed")
                self.last_sync_success = False
                self.last_sync_time = datetime.utcnow()
                return False
            
            # Save to temporary file first
            temp_path = self.feed_path.with_suffix('.tmp')
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(feed_data, f, indent=2)
            
            # Atomic replacement
            temp_path.replace(self.feed_path)
            
            ioc_count = len(feed_data.get('iocs', []))
            logger.info(f"Feed sync successful: {ioc_count} IOCs updated")
            
            self.last_sync_time = datetime.utcnow()
            self.last_sync_success = True
            return True
            
        except Exception as e:
            logger.error(f"Feed sync failed: {e}")
            self.last_sync_success = False
            self.last_sync_time = datetime.utcnow()
            return False
    
    def _download_feed(self) -> Optional[Dict]:
        """
        Download IOC feed from backend API.
        
        Returns:
            Feed data as dictionary or None on failure
        """
        headers = {}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        try:
            response = requests.get(
                self.feed_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Backend returned status {response.status_code}: {response.text[:200]}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout after {self.timeout}s")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {e}")
            return None
    
    def _validate_feed(self, feed_data: Dict) -> bool:
        """
        Validate feed data structure.
        
        Args:
            feed_data: Feed data to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        if not isinstance(feed_data, dict):
            logger.error("Feed data is not a dictionary")
            return False
        
        if 'iocs' not in feed_data:
            logger.error("Feed missing 'iocs' field")
            return False
        
        if not isinstance(feed_data['iocs'], list):
            logger.error("'iocs' field is not a list")
            return False
        
        # Validate each IOC
        for idx, ioc in enumerate(feed_data['iocs']):
            if not isinstance(ioc, dict):
                logger.warning(f"IOC at index {idx} is not a dictionary")
                continue
            
            # Check required IOC fields
            required_fields = ['ioc_type', 'value']
            for field in required_fields:
                if field not in ioc:
                    logger.warning(f"IOC at index {idx} missing required field: {field}")
                    return False
            
            # Validate IOC type
            valid_types = ['ip', 'domain', 'hash', 'registry', 'url']
            if ioc['ioc_type'] not in valid_types:
                logger.warning(f"IOC at index {idx} has invalid type: {ioc['ioc_type']}")
                continue
        
        logger.info(f"Feed validation passed: {len(feed_data['iocs'])} IOCs")
        return True
    
    def get_sync_status(self) -> Dict:
        """
        Get current synchronization status.
        
        Returns:
            Status dictionary
        """
        status = {
            'running': self.running,
            'last_sync_time': self.last_sync_time.isoformat() + "Z" if self.last_sync_time else None,
            'last_sync_success': self.last_sync_success,
            'sync_interval_minutes': self.sync_interval,
            'feed_url': self.feed_url,
            'feed_path': str(self.feed_path)
        }
        
        # Calculate next sync time
        if self.last_sync_time and self.running:
            next_sync = self.last_sync_time + timedelta(minutes=self.sync_interval)
            status['next_sync_time'] = next_sync.isoformat() + "Z"
            status['seconds_until_next_sync'] = max(0, int((next_sync - datetime.utcnow()).total_seconds()))
        
        return status
    
    def force_sync(self) -> bool:
        """
        Force an immediate feed synchronization.
        
        Returns:
            True if successful, False otherwise
        """
        logger.info("Manual feed sync triggered")
        return self.sync_feeds()


class STIXParser:
    """
    Parser for STIX 2.x threat intelligence feeds.
    
    Converts STIX bundles to TamsilCMS IOC format.
    """
    
    @staticmethod
    def parse_stix_bundle(bundle: Dict) -> List[Dict]:
        """
        Parse STIX 2.x bundle into IOC list.
        
        Args:
            bundle: STIX bundle dictionary
            
        Returns:
            List of IOC dictionaries
        """
        iocs = []
        
        if 'objects' not in bundle:
            logger.warning("STIX bundle missing 'objects' field")
            return iocs
        
        for obj in bundle['objects']:
            obj_type = obj.get('type')
            
            if obj_type == 'indicator':
                ioc = STIXParser._parse_indicator(obj)
                if ioc:
                    iocs.append(ioc)
            
            elif obj_type == 'threat-actor':
                # Store threat actor info for enrichment
                pass
            
            elif obj_type == 'campaign':
                # Store campaign info for enrichment
                pass
        
        return iocs
    
    @staticmethod
    def _parse_indicator(indicator: Dict) -> Optional[Dict]:
        """
        Parse STIX indicator object to IOC.
        
        Args:
            indicator: STIX indicator object
            
        Returns:
            IOC dictionary or None
        """
        pattern = indicator.get('pattern', '')
        
        # Extract IOC from STIX pattern
        # Example: [ipv4-addr:value = '192.168.1.1']
        # Example: [domain-name:value = 'evil.com']
        # Example: [file:hashes.MD5 = 'abc123']
        
        ioc_type = None
        value = None
        
        # Simple pattern extraction (could be enhanced with proper STIX pattern parser)
        if 'ipv4-addr:value' in pattern or 'ipv6-addr:value' in pattern:
            ioc_type = 'ip'
            # Extract IP from pattern
            import re
            match = re.search(r"'([^']+)'", pattern)
            if match:
                value = match.group(1)
        
        elif 'domain-name:value' in pattern:
            ioc_type = 'domain'
            import re
            match = re.search(r"'([^']+)'", pattern)
            if match:
                value = match.group(1)
        
        elif 'file:hashes' in pattern:
            ioc_type = 'hash'
            import re
            match = re.search(r"'([^']+)'", pattern)
            if match:
                value = match.group(1)
        
        if not ioc_type or not value:
            return None
        
        # Build IOC
        ioc = {
            'ioc_type': ioc_type,
            'value': value,
            'description': indicator.get('description', ''),
            'confidence': STIXParser._map_confidence(indicator.get('confidence', 50)),
            'tags': indicator.get('labels', []),
            'first_seen': indicator.get('created'),
            'last_seen': indicator.get('modified'),
            'source': 'stix'
        }
        
        return ioc
    
    @staticmethod
    def _map_confidence(stix_confidence: int) -> float:
        """
        Map STIX confidence (0-100) to IOC confidence (0.0-1.0).
        
        Args:
            stix_confidence: STIX confidence value
            
        Returns:
            Normalized confidence
        """
        return min(1.0, max(0.0, stix_confidence / 100.0))


def main():
    """CLI interface for feed sync manager."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Load config
    config = {
        'threat_intel': {
            'feed_url': 'https://backend.tamsilcms.local/api/intel/iocs',
            'feed_path': '/var/tamsilcms/intel/iocs.json',
            'sync_interval_minutes': 60,
            'verify_ssl': True,
            'timeout_seconds': 30
        }
    }
    
    manager = FeedSyncManager(config)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python feed_sync.py sync        - Perform one-time sync")
        print("  python feed_sync.py status      - Show sync status")
        print("  python feed_sync.py daemon      - Run continuous sync loop")
        return
    
    command = sys.argv[1]
    
    if command == "sync":
        success = manager.sync_feeds()
        if success:
            print("\n✅ Feed sync successful")
            sys.exit(0)
        else:
            print("\n❌ Feed sync failed")
            sys.exit(1)
    
    elif command == "status":
        status = manager.get_sync_status()
        print("\nFeed Sync Status:")
        print(f"  Running: {status['running']}")
        print(f"  Last Sync: {status['last_sync_time'] or 'Never'}")
        print(f"  Last Success: {status['last_sync_success']}")
        print(f"  Sync Interval: {status['sync_interval_minutes']} minutes")
        print(f"  Feed URL: {status['feed_url']}")
        print(f"  Feed Path: {status['feed_path']}")
        if 'next_sync_time' in status:
            print(f"  Next Sync: {status['next_sync_time']} ({status['seconds_until_next_sync']}s)")
    
    elif command == "daemon":
        print("Starting feed sync daemon...")
        print(f"Sync interval: {config['threat_intel']['sync_interval_minutes']} minutes")
        print("Press Ctrl+C to stop\n")
        
        manager.start_sync_loop()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            manager.stop_sync_loop()
    
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()
