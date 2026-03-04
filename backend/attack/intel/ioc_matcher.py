"""
IOC Matcher Module
Matches indicators of compromise (IOCs) from threat intelligence feeds.

Supports:
- IP addresses (IPv4/IPv6)
- Domain names
- File hashes (MD5, SHA1, SHA256)
- Registry keys (Windows)
- URL patterns
- Threat actor attribution
"""

import json
import logging
import re
import ipaddress
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Represents an indicator of compromise."""
    ioc_type: str  # ip, domain, hash, registry, url
    value: str
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    confidence: float = 0.5  # 0.0 to 1.0
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""
    tags: List[str] = None
    first_seen: str = None
    last_seen: str = None
    source: str = "unknown"
    ttl_hours: int = 720  # 30 days default
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.first_seen is None:
            self.first_seen = datetime.utcnow().isoformat() + "Z"
        if self.last_seen is None:
            self.last_seen = self.first_seen
    
    def is_expired(self) -> bool:
        """Check if IOC has expired based on TTL."""
        if not self.last_seen:
            return False
        
        try:
            last_seen_dt = datetime.fromisoformat(self.last_seen.replace('Z', '+00:00'))
            expiry_dt = last_seen_dt + timedelta(hours=self.ttl_hours)
            return datetime.utcnow() > expiry_dt.replace(tzinfo=None)
        except Exception as e:
            logger.warning(f"Failed to check IOC expiry: {e}")
            return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class IOCMatch:
    """Represents a match between telemetry and an IOC."""
    ioc: IOC
    matched_value: str
    context: Dict  # Additional context from telemetry
    timestamp: str
    alert_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'ioc': self.ioc.to_dict(),
            'matched_value': self.matched_value,
            'context': self.context,
            'timestamp': self.timestamp,
            'alert_id': self.alert_id
        }


class IOCMatcher:
    """
    Matches telemetry against threat intelligence IOCs.
    
    Supports multiple IOC types and provides enrichment with
    threat actor and campaign attribution.
    """
    
    def __init__(self, ioc_feed_path: str = "/var/tamsilcms/intel/iocs.json"):
        """
        Initialize IOC matcher.
        
        Args:
            ioc_feed_path: Path to IOC feed JSON file
        """
        self.ioc_feed_path = Path(ioc_feed_path)
        self.iocs: Dict[str, List[IOC]] = {
            'ip': [],
            'domain': [],
            'hash': [],
            'registry': [],
            'url': []
        }
        self.ioc_index: Dict[str, IOC] = {}  # value -> IOC for fast lookup
        
        self._load_iocs()
        
        logger.info(f"IOC matcher initialized with {self._count_iocs()} indicators")
    
    def _count_iocs(self) -> int:
        """Count total IOCs loaded."""
        return sum(len(ioc_list) for ioc_list in self.iocs.values())
    
    def _load_iocs(self):
        """Load IOCs from feed file."""
        if not self.ioc_feed_path.exists():
            logger.warning(f"IOC feed not found at {self.ioc_feed_path}, using sample IOCs")
            self._load_sample_iocs()
            return
        
        try:
            with open(self.ioc_feed_path, 'r', encoding='utf-8') as f:
                feed_data = json.load(f)
            
            if isinstance(feed_data, list):
                for ioc_data in feed_data:
                    self._add_ioc_from_dict(ioc_data)
            elif isinstance(feed_data, dict) and 'iocs' in feed_data:
                for ioc_data in feed_data['iocs']:
                    self._add_ioc_from_dict(ioc_data)
            
            # Remove expired IOCs
            self._cleanup_expired_iocs()
            
            logger.info(f"Loaded {self._count_iocs()} IOCs from feed")
            
        except Exception as e:
            logger.error(f"Failed to load IOC feed: {e}")
            self._load_sample_iocs()
    
    def _add_ioc_from_dict(self, ioc_data: Dict):
        """Parse and add an IOC from dictionary."""
        try:
            ioc = IOC(
                ioc_type=ioc_data['ioc_type'],
                value=ioc_data['value'],
                threat_actor=ioc_data.get('threat_actor'),
                campaign=ioc_data.get('campaign'),
                confidence=ioc_data.get('confidence', 0.5),
                severity=ioc_data.get('severity', 'medium'),
                description=ioc_data.get('description', ''),
                tags=ioc_data.get('tags', []),
                first_seen=ioc_data.get('first_seen'),
                last_seen=ioc_data.get('last_seen'),
                source=ioc_data.get('source', 'feed'),
                ttl_hours=ioc_data.get('ttl_hours', 720)
            )
            
            if ioc.ioc_type in self.iocs:
                self.iocs[ioc.ioc_type].append(ioc)
                self.ioc_index[ioc.value.lower()] = ioc
            else:
                logger.warning(f"Unknown IOC type: {ioc.ioc_type}")
                
        except Exception as e:
            logger.error(f"Failed to parse IOC: {e}")
    
    def _load_sample_iocs(self):
        """Load sample IOCs for testing and demonstration."""
        sample_iocs = [
            # Ransomware-related IPs
            IOC(
                ioc_type="ip",
                value="185.220.101.1",
                threat_actor="REvil",
                campaign="REvil-2023",
                confidence=0.85,
                severity="high",
                description="C2 server associated with REvil ransomware",
                tags=["ransomware", "c2", "revil"],
                source="sample"
            ),
            IOC(
                ioc_type="ip",
                value="45.142.212.61",
                threat_actor="LockBit",
                campaign="LockBit-3.0",
                confidence=0.90,
                severity="critical",
                description="LockBit 3.0 infrastructure",
                tags=["ransomware", "lockbit"],
                source="sample"
            ),
            
            # Malicious domains
            IOC(
                ioc_type="domain",
                value="evil-ransom.ru",
                threat_actor="Unknown",
                confidence=0.75,
                severity="high",
                description="Domain hosting ransomware payloads",
                tags=["malware", "ransomware"],
                source="sample"
            ),
            IOC(
                ioc_type="domain",
                value="crypto-locker-pay.com",
                threat_actor="CryptoLocker",
                campaign="CryptoLocker-2024",
                confidence=0.80,
                severity="high",
                description="Payment portal for CryptoLocker",
                tags=["ransomware", "payment"],
                source="sample"
            ),
            
            # Malware hashes
            IOC(
                ioc_type="hash",
                value="44d88612fea8a8f36de82e1278abb02f",  # MD5
                threat_actor="WannaCry",
                confidence=0.95,
                severity="critical",
                description="WannaCry ransomware executable",
                tags=["ransomware", "wannacry"],
                source="sample"
            ),
            IOC(
                ioc_type="hash",
                value="3395856ce81f2b7382dee72602f798b642f14140",  # SHA1
                threat_actor="Petya",
                confidence=0.90,
                severity="critical",
                description="Petya/NotPetya ransomware",
                tags=["ransomware", "petya"],
                source="sample"
            ),
            IOC(
                ioc_type="hash",
                value="9518f8b0d1e8d6a7c6e2e8b8c1f5d4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7",  # SHA256
                threat_actor="Ryuk",
                campaign="Ryuk-2024",
                confidence=0.92,
                severity="critical",
                description="Ryuk ransomware payload",
                tags=["ransomware", "ryuk"],
                source="sample"
            ),
            
            # Registry persistence keys
            IOC(
                ioc_type="registry",
                value="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalwareStartup",
                confidence=0.85,
                severity="high",
                description="Malware persistence via Run key",
                tags=["persistence", "registry"],
                source="sample"
            ),
        ]
        
        for ioc in sample_iocs:
            self.iocs[ioc.ioc_type].append(ioc)
            self.ioc_index[ioc.value.lower()] = ioc
        
        logger.info(f"Loaded {len(sample_iocs)} sample IOCs")
    
    def _cleanup_expired_iocs(self):
        """Remove expired IOCs from memory."""
        expired_count = 0
        
        for ioc_type in self.iocs.keys():
            active_iocs = []
            for ioc in self.iocs[ioc_type]:
                if not ioc.is_expired():
                    active_iocs.append(ioc)
                else:
                    expired_count += 1
                    # Remove from index
                    self.ioc_index.pop(ioc.value.lower(), None)
            
            self.iocs[ioc_type] = active_iocs
        
        if expired_count > 0:
            logger.info(f"Removed {expired_count} expired IOCs")
    
    def match_ip(self, ip_address: str, context: Dict = None) -> Optional[IOCMatch]:
        """
        Match an IP address against IOC feed.
        
        Args:
            ip_address: IP address to check
            context: Additional context (process, connection, etc.)
            
        Returns:
            IOCMatch if found, None otherwise
        """
        # Normalize IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            normalized_ip = str(ip_obj)
        except ValueError:
            logger.debug(f"Invalid IP address: {ip_address}")
            return None
        
        # Check exact match
        ioc = self.ioc_index.get(normalized_ip.lower())
        if ioc and ioc.ioc_type == 'ip':
            return IOCMatch(
                ioc=ioc,
                matched_value=normalized_ip,
                context=context or {},
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
        
        return None
    
    def match_domain(self, domain: str, context: Dict = None) -> Optional[IOCMatch]:
        """
        Match a domain name against IOC feed.
        
        Args:
            domain: Domain name to check
            context: Additional context
            
        Returns:
            IOCMatch if found, None otherwise
        """
        domain_lower = domain.lower().strip()
        
        # Check exact match
        ioc = self.ioc_index.get(domain_lower)
        if ioc and ioc.ioc_type == 'domain':
            return IOCMatch(
                ioc=ioc,
                matched_value=domain,
                context=context or {},
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
        
        # Check subdomain matching
        for ioc in self.iocs['domain']:
            if domain_lower.endswith('.' + ioc.value.lower()) or domain_lower == ioc.value.lower():
                return IOCMatch(
                    ioc=ioc,
                    matched_value=domain,
                    context=context or {},
                    timestamp=datetime.utcnow().isoformat() + "Z"
                )
        
        return None
    
    def match_hash(self, file_hash: str, hash_type: str = None, context: Dict = None) -> Optional[IOCMatch]:
        """
        Match a file hash against IOC feed.
        
        Args:
            file_hash: File hash to check
            hash_type: Type of hash (md5, sha1, sha256) - auto-detected if None
            context: Additional context (file path, process, etc.)
            
        Returns:
            IOCMatch if found, None otherwise
        """
        hash_lower = file_hash.lower().strip()
        
        # Auto-detect hash type if not provided
        if not hash_type:
            hash_len = len(hash_lower)
            if hash_len == 32:
                hash_type = 'md5'
            elif hash_len == 40:
                hash_type = 'sha1'
            elif hash_len == 64:
                hash_type = 'sha256'
            else:
                logger.debug(f"Unknown hash length: {hash_len}")
                return None
        
        # Check exact match
        ioc = self.ioc_index.get(hash_lower)
        if ioc and ioc.ioc_type == 'hash':
            return IOCMatch(
                ioc=ioc,
                matched_value=file_hash,
                context=context or {'hash_type': hash_type},
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
        
        return None
    
    def match_registry(self, registry_path: str, context: Dict = None) -> Optional[IOCMatch]:
        """
        Match a registry key against IOC feed.
        
        Args:
            registry_path: Registry path to check
            context: Additional context
            
        Returns:
            IOCMatch if found, None otherwise
        """
        reg_lower = registry_path.lower().strip()
        
        # Check exact match
        ioc = self.ioc_index.get(reg_lower)
        if ioc and ioc.ioc_type == 'registry':
            return IOCMatch(
                ioc=ioc,
                matched_value=registry_path,
                context=context or {},
                timestamp=datetime.utcnow().isoformat() + "Z"
            )
        
        # Check partial matches (registry paths can have variations)
        for ioc in self.iocs['registry']:
            if ioc.value.lower() in reg_lower or reg_lower in ioc.value.lower():
                return IOCMatch(
                    ioc=ioc,
                    matched_value=registry_path,
                    context=context or {},
                    timestamp=datetime.utcnow().isoformat() + "Z"
                )
        
        return None
    
    def match_telemetry(self, telemetry: Dict) -> List[IOCMatch]:
        """
        Match telemetry event against all IOC types.
        
        Args:
            telemetry: Telemetry event dictionary
            
        Returns:
            List of IOC matches found
        """
        matches = []
        
        # Extract potential IOCs from telemetry
        # Network connections
        if 'network' in telemetry:
            net_data = telemetry['network']
            for ip_field in ['remote_ip', 'dst_ip', 'source_ip', 'destination_ip']:
                if ip_field in net_data:
                    match = self.match_ip(net_data[ip_field], {'telemetry_type': 'network'})
                    if match:
                        matches.append(match)
            
            for domain_field in ['domain', 'hostname', 'dns_query']:
                if domain_field in net_data:
                    match = self.match_domain(net_data[domain_field], {'telemetry_type': 'network'})
                    if match:
                        matches.append(match)
        
        # File operations
        if 'file' in telemetry:
            file_data = telemetry['file']
            for hash_field in ['md5', 'sha1', 'sha256', 'hash']:
                if hash_field in file_data:
                    match = self.match_hash(file_data[hash_field], hash_field, {'telemetry_type': 'file'})
                    if match:
                        matches.append(match)
        
        # Registry operations
        if 'registry' in telemetry:
            reg_data = telemetry['registry']
            if 'path' in reg_data or 'key' in reg_data:
                reg_path = reg_data.get('path') or reg_data.get('key')
                match = self.match_registry(reg_path, {'telemetry_type': 'registry'})
                if match:
                    matches.append(match)
        
        # Process creation
        if 'process' in telemetry:
            proc_data = telemetry['process']
            # Check process hashes
            for hash_field in ['md5', 'sha1', 'sha256', 'hash']:
                if hash_field in proc_data:
                    match = self.match_hash(proc_data[hash_field], hash_field, {'telemetry_type': 'process'})
                    if match:
                        matches.append(match)
        
        return matches
    
    def add_ioc(self, ioc: IOC):
        """
        Add a new IOC to the matcher.
        
        Args:
            ioc: IOC object to add
        """
        if ioc.ioc_type not in self.iocs:
            logger.warning(f"Unknown IOC type: {ioc.ioc_type}")
            return
        
        self.iocs[ioc.ioc_type].append(ioc)
        self.ioc_index[ioc.value.lower()] = ioc
        logger.info(f"Added IOC: {ioc.ioc_type} - {ioc.value}")
    
    def remove_ioc(self, value: str) -> bool:
        """
        Remove an IOC by value.
        
        Args:
            value: IOC value to remove
            
        Returns:
            True if removed, False if not found
        """
        value_lower = value.lower()
        ioc = self.ioc_index.get(value_lower)
        
        if not ioc:
            return False
        
        # Remove from type list
        self.iocs[ioc.ioc_type] = [i for i in self.iocs[ioc.ioc_type] if i.value.lower() != value_lower]
        
        # Remove from index
        del self.ioc_index[value_lower]
        
        logger.info(f"Removed IOC: {value}")
        return True
    
    def get_iocs_by_actor(self, actor: str) -> List[IOC]:
        """
        Get all IOCs associated with a threat actor.
        
        Args:
            actor: Threat actor name
            
        Returns:
            List of IOCs
        """
        results = []
        actor_lower = actor.lower()
        
        for ioc_list in self.iocs.values():
            for ioc in ioc_list:
                if ioc.threat_actor and actor_lower in ioc.threat_actor.lower():
                    results.append(ioc)
        
        return results
    
    def get_iocs_by_campaign(self, campaign: str) -> List[IOC]:
        """
        Get all IOCs associated with a campaign.
        
        Args:
            campaign: Campaign name
            
        Returns:
            List of IOCs
        """
        results = []
        campaign_lower = campaign.lower()
        
        for ioc_list in self.iocs.values():
            for ioc in ioc_list:
                if ioc.campaign and campaign_lower in ioc.campaign.lower():
                    results.append(ioc)
        
        return results
    
    def export_iocs(self, output_path: str):
        """
        Export all IOCs to JSON file.
        
        Args:
            output_path: Path to output file
        """
        all_iocs = []
        for ioc_list in self.iocs.values():
            all_iocs.extend([ioc.to_dict() for ioc in ioc_list])
        
        feed_data = {
            'version': '1.0',
            'generated_at': datetime.utcnow().isoformat() + "Z",
            'ioc_count': len(all_iocs),
            'iocs': all_iocs
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(feed_data, f, indent=2)
        
        logger.info(f"Exported {len(all_iocs)} IOCs to {output_path}")
    
    def get_statistics(self) -> Dict:
        """
        Get IOC statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total': self._count_iocs(),
            'by_type': {k: len(v) for k, v in self.iocs.items()},
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'threat_actors': set(),
            'campaigns': set()
        }
        
        for ioc_list in self.iocs.values():
            for ioc in ioc_list:
                stats['by_severity'][ioc.severity] += 1
                if ioc.threat_actor:
                    stats['threat_actors'].add(ioc.threat_actor)
                if ioc.campaign:
                    stats['campaigns'].add(ioc.campaign)
        
        stats['threat_actors'] = list(stats['threat_actors'])
        stats['campaigns'] = list(stats['campaigns'])
        
        return stats


def main():
    """CLI interface for IOC matcher."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    matcher = IOCMatcher()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ioc_matcher.py check ip <address>       - Check IP address")
        print("  python ioc_matcher.py check domain <name>      - Check domain name")
        print("  python ioc_matcher.py check hash <value>       - Check file hash")
        print("  python ioc_matcher.py actor <name>             - List IOCs for actor")
        print("  python ioc_matcher.py campaign <name>          - List IOCs for campaign")
        print("  python ioc_matcher.py stats                    - Show statistics")
        print("  python ioc_matcher.py export <path>            - Export IOCs to JSON")
        return
    
    command = sys.argv[1]
    
    if command == "check" and len(sys.argv) > 3:
        ioc_type = sys.argv[2]
        value = sys.argv[3]
        
        match = None
        if ioc_type == "ip":
            match = matcher.match_ip(value)
        elif ioc_type == "domain":
            match = matcher.match_domain(value)
        elif ioc_type == "hash":
            match = matcher.match_hash(value)
        
        if match:
            print(f"\n🚨 MATCH FOUND for {value}\n")
            ioc = match.ioc
            print(f"Type: {ioc.ioc_type}")
            print(f"Threat Actor: {ioc.threat_actor or 'Unknown'}")
            print(f"Campaign: {ioc.campaign or 'Unknown'}")
            print(f"Severity: {ioc.severity.upper()}")
            print(f"Confidence: {ioc.confidence * 100:.0f}%")
            print(f"Description: {ioc.description}")
            print(f"Tags: {', '.join(ioc.tags)}")
        else:
            print(f"✅ No match found for {value}")
    
    elif command == "actor" and len(sys.argv) > 2:
        actor = ' '.join(sys.argv[2:])
        iocs = matcher.get_iocs_by_actor(actor)
        print(f"\nFound {len(iocs)} IOCs for threat actor '{actor}':\n")
        for ioc in iocs:
            print(f"  {ioc.ioc_type}: {ioc.value} ({ioc.severity})")
    
    elif command == "campaign" and len(sys.argv) > 2:
        campaign = ' '.join(sys.argv[2:])
        iocs = matcher.get_iocs_by_campaign(campaign)
        print(f"\nFound {len(iocs)} IOCs for campaign '{campaign}':\n")
        for ioc in iocs:
            print(f"  {ioc.ioc_type}: {ioc.value} ({ioc.severity})")
    
    elif command == "stats":
        stats = matcher.get_statistics()
        print("\nIOC Statistics:")
        print(f"  Total IOCs: {stats['total']}")
        print(f"\n  By Type:")
        for ioc_type, count in stats['by_type'].items():
            print(f"    {ioc_type}: {count}")
        print(f"\n  By Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"    {severity}: {count}")
        print(f"\n  Threat Actors: {len(stats['threat_actors'])}")
        print(f"  Campaigns: {len(stats['campaigns'])}")
    
    elif command == "export" and len(sys.argv) > 2:
        output_path = sys.argv[2]
        matcher.export_iocs(output_path)
        print(f"IOCs exported to {output_path}")
    
    else:
        print("Unknown command or missing arguments")


if __name__ == "__main__":
    main()
