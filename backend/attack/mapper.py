"""
ATT&CK Mapper Module
Maps detections to MITRE ATT&CK techniques and tactics.

Provides:
- Technique ID tagging for detections
- Tactic categorization
- Sub-technique resolution
- Confidence scoring
- Detection-to-technique mapping
"""

import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactics: List[str]
    description: str
    data_sources: List[str]
    platforms: List[str]
    sub_techniques: List[str] = None
    
    def __post_init__(self):
        if self.sub_techniques is None:
            self.sub_techniques = []


@dataclass
class TechniqueMapping:
    """Maps a detection to ATT&CK techniques."""
    detection_name: str
    techniques: List[str]  # Technique IDs like T1486, T1003.001
    tactics: List[str]  # Tactic names like "Impact", "Credential Access"
    confidence: float  # 0.0 to 1.0
    rationale: str  # Why this mapping exists
    data_sources: List[str]  # Required data sources
    timestamp: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class AttackMapper:
    """
    Maps detections to MITRE ATT&CK framework.
    
    Provides technique tagging, tactic categorization, and enrichment
    for all detection events.
    """
    
    def __init__(self, matrix_path: str = "/var/tamsilcms/attack/enterprise-attack.json"):
        """
        Initialize ATT&CK mapper.
        
        Args:
            matrix_path: Path to ATT&CK matrix JSON file
        """
        self.matrix_path = Path(matrix_path)
        self.techniques: Dict[str, AttackTechnique] = {}
        self.tactics: Dict[str, List[str]] = {}  # tactic -> technique IDs
        self.detection_mappings: Dict[str, TechniqueMapping] = {}
        
        self._load_matrix()
        self._load_detection_mappings()
        
        logger.info(f"ATT&CK mapper initialized with {len(self.techniques)} techniques")
    
    def _load_matrix(self):
        """Load ATT&CK matrix from JSON file."""
        if not self.matrix_path.exists():
            logger.warning(f"ATT&CK matrix not found at {self.matrix_path}, using embedded mappings")
            self._load_embedded_matrix()
            return
        
        try:
            with open(self.matrix_path, 'r', encoding='utf-8') as f:
                matrix_data = json.load(f)
            
            # Parse STIX bundle format
            if 'objects' in matrix_data:
                for obj in matrix_data['objects']:
                    if obj.get('type') == 'attack-pattern':
                        self._parse_technique(obj)
            
            logger.info(f"Loaded {len(self.techniques)} techniques from ATT&CK matrix")
            
        except Exception as e:
            logger.error(f"Failed to load ATT&CK matrix: {e}")
            self._load_embedded_matrix()
    
    def _parse_technique(self, obj: Dict):
        """Parse a technique object from STIX format."""
        # Extract technique ID from external references
        tech_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                break
        
        if not tech_id:
            return
        
        # Extract kill chain phases (tactics)
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic = phase.get('phase_name', '').replace('-', ' ').title()
                tactics.append(tactic)
        
        # Parse data sources
        data_sources = []
        for source in obj.get('x_mitre_data_sources', []):
            data_sources.append(source)
        
        # Parse platforms
        platforms = obj.get('x_mitre_platforms', [])
        
        # Check if this is a sub-technique
        parent_id = None
        if '.' in tech_id:
            parent_id = tech_id.split('.')[0]
        
        technique = AttackTechnique(
            technique_id=tech_id,
            technique_name=obj.get('name', ''),
            tactics=tactics,
            description=obj.get('description', ''),
            data_sources=data_sources,
            platforms=platforms,
            sub_techniques=[]
        )
        
        self.techniques[tech_id] = technique
        
        # Index by tactic
        for tactic in tactics:
            if tactic not in self.tactics:
                self.tactics[tactic] = []
            self.tactics[tactic].append(tech_id)
        
        # Link sub-technique to parent
        if parent_id and parent_id in self.techniques:
            self.techniques[parent_id].sub_techniques.append(tech_id)
    
    def _load_embedded_matrix(self):
        """Load minimal embedded ATT&CK matrix for common techniques."""
        embedded_techniques = [
            # Ransomware-related
            ("T1486", "Data Encrypted for Impact", ["Impact"], 
             "Adversary encrypted data to interrupt availability", ["Windows", "Linux", "macOS"]),
            ("T1490", "Inhibit System Recovery", ["Impact"],
             "Delete or inhibit system recovery capabilities", ["Windows", "Linux", "macOS"]),
            ("T1485", "Data Destruction", ["Impact"],
             "Destroy data and files on specific systems", ["Windows", "Linux", "macOS"]),
            
            # Credential Access
            ("T1003", "OS Credential Dumping", ["Credential Access"],
             "Dump credentials from operating system", ["Windows", "Linux", "macOS"]),
            ("T1003.001", "LSASS Memory", ["Credential Access"],
             "Dump LSASS memory to obtain credentials", ["Windows"]),
            ("T1555", "Credentials from Password Stores", ["Credential Access"],
             "Search for stored credentials in password stores", ["Windows", "Linux", "macOS"]),
            
            # Persistence
            ("T1547", "Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"],
             "Configure system to execute during boot or logon", ["Windows", "Linux", "macOS"]),
            ("T1053", "Scheduled Task/Job", ["Persistence", "Privilege Escalation"],
             "Schedule code execution at specific times", ["Windows", "Linux", "macOS"]),
            
            # Defense Evasion
            ("T1562", "Impair Defenses", ["Defense Evasion"],
             "Prevent or disable security tools", ["Windows", "Linux", "macOS"]),
            ("T1070", "Indicator Removal", ["Defense Evasion"],
             "Delete or modify artifacts to evade detection", ["Windows", "Linux", "macOS"]),
            ("T1027", "Obfuscated Files or Information", ["Defense Evasion"],
             "Make files or information difficult to discover", ["Windows", "Linux", "macOS"]),
            
            # Discovery
            ("T1082", "System Information Discovery", ["Discovery"],
             "Gather system and environment information", ["Windows", "Linux", "macOS"]),
            ("T1083", "File and Directory Discovery", ["Discovery"],
             "Enumerate files and directories", ["Windows", "Linux", "macOS"]),
            ("T1057", "Process Discovery", ["Discovery"],
             "Get information about running processes", ["Windows", "Linux", "macOS"]),
            
            # Execution
            ("T1059", "Command and Scripting Interpreter", ["Execution"],
             "Execute commands via interpreters", ["Windows", "Linux", "macOS"]),
            ("T1106", "Native API", ["Execution"],
             "Execute via native OS APIs", ["Windows", "Linux", "macOS"]),
        ]
        
        for tech_id, name, tactics, desc, platforms in embedded_techniques:
            technique = AttackTechnique(
                technique_id=tech_id,
                technique_name=name,
                tactics=tactics,
                description=desc,
                data_sources=[],
                platforms=platforms,
                sub_techniques=[]
            )
            self.techniques[tech_id] = technique
            
            for tactic in tactics:
                if tactic not in self.tactics:
                    self.tactics[tactic] = []
                self.tactics[tactic].append(tech_id)
        
        logger.info(f"Loaded {len(embedded_techniques)} embedded techniques")
    
    def _load_detection_mappings(self):
        """Load detection-to-technique mappings."""
        # Define mappings for Track 2 detections
        mappings = [
            TechniqueMapping(
                detection_name="ransomware_file_encryption",
                techniques=["T1486"],
                tactics=["Impact"],
                confidence=0.95,
                rationale="High-volume file modifications with suspicious extensions indicate ransomware encryption",
                data_sources=["File: File Modification"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="ransomware_mass_deletion",
                techniques=["T1485", "T1490"],
                tactics=["Impact"],
                confidence=0.85,
                rationale="Mass file deletion may indicate data destruction or inhibiting recovery",
                data_sources=["File: File Deletion"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="ransomware_note_creation",
                techniques=["T1486"],
                tactics=["Impact"],
                confidence=0.98,
                rationale="Creation of ransom note files is direct indicator of ransomware",
                data_sources=["File: File Creation"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="suspicious_process_execution",
                techniques=["T1059", "T1106"],
                tactics=["Execution"],
                confidence=0.70,
                rationale="Execution of suspicious processes or scripts",
                data_sources=["Process: Process Creation"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="credential_dumping",
                techniques=["T1003", "T1003.001"],
                tactics=["Credential Access"],
                confidence=0.90,
                rationale="LSASS memory access or credential file access",
                data_sources=["Process: Process Access"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="defense_evasion_av_disable",
                techniques=["T1562"],
                tactics=["Defense Evasion"],
                confidence=0.95,
                rationale="Attempt to disable antivirus or security tools",
                data_sources=["Service: Service Metadata", "Process: Process Termination"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
            TechniqueMapping(
                detection_name="persistence_scheduled_task",
                techniques=["T1053"],
                tactics=["Persistence", "Privilege Escalation"],
                confidence=0.80,
                rationale="Creation of scheduled task for persistence",
                data_sources=["Scheduled Job: Scheduled Job Creation"],
                timestamp=datetime.utcnow().isoformat() + "Z"
            ),
        ]
        
        for mapping in mappings:
            self.detection_mappings[mapping.detection_name] = mapping
    
    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich an alert with ATT&CK technique information.
        
        Args:
            alert: Alert dictionary to enrich
            
        Returns:
            Enriched alert with ATT&CK context
        """
        detection_type = alert.get('type', '')
        enriched = alert.copy()
        
        # Find matching detection mapping
        mapping = self.detection_mappings.get(detection_type)
        if not mapping:
            # Try partial matching
            for det_name, det_mapping in self.detection_mappings.items():
                if det_name in detection_type or detection_type in det_name:
                    mapping = det_mapping
                    break
        
        if not mapping:
            logger.debug(f"No ATT&CK mapping found for detection type: {detection_type}")
            return enriched
        
        # Add ATT&CK context
        attack_context = {
            'techniques': [],
            'tactics': mapping.tactics,
            'confidence': mapping.confidence,
            'data_sources': mapping.data_sources
        }
        
        # Enrich each technique
        for tech_id in mapping.techniques:
            technique = self.techniques.get(tech_id)
            if technique:
                attack_context['techniques'].append({
                    'id': tech_id,
                    'name': technique.technique_name,
                    'tactics': technique.tactics,
                    'url': f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                })
        
        enriched['attack'] = attack_context
        enriched['enriched_at'] = datetime.utcnow().isoformat() + "Z"
        
        return enriched
    
    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """
        Get technique details by ID.
        
        Args:
            technique_id: Technique ID (e.g., "T1486")
            
        Returns:
            AttackTechnique object or None
        """
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[str]:
        """
        Get all technique IDs for a tactic.
        
        Args:
            tactic: Tactic name (e.g., "Impact")
            
        Returns:
            List of technique IDs
        """
        return self.tactics.get(tactic, [])
    
    def search_techniques(self, query: str) -> List[AttackTechnique]:
        """
        Search techniques by name or description.
        
        Args:
            query: Search query
            
        Returns:
            List of matching techniques
        """
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques.values():
            if (query_lower in technique.technique_name.lower() or
                query_lower in technique.description.lower() or
                query_lower in technique.technique_id.lower()):
                results.append(technique)
        
        return results
    
    def get_detection_mapping(self, detection_name: str) -> Optional[TechniqueMapping]:
        """
        Get ATT&CK mapping for a detection.
        
        Args:
            detection_name: Name of the detection
            
        Returns:
            TechniqueMapping or None
        """
        return self.detection_mappings.get(detection_name)
    
    def add_detection_mapping(self, mapping: TechniqueMapping):
        """
        Add or update a detection mapping.
        
        Args:
            mapping: TechniqueMapping to add
        """
        self.detection_mappings[mapping.detection_name] = mapping
        logger.info(f"Added detection mapping: {mapping.detection_name} -> {mapping.techniques}")
    
    def export_mappings(self, output_path: str):
        """
        Export all detection mappings to JSON.
        
        Args:
            output_path: Path to output file
        """
        mappings_list = [m.to_dict() for m in self.detection_mappings.values()]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(mappings_list, f, indent=2)
        
        logger.info(f"Exported {len(mappings_list)} mappings to {output_path}")
    
    def get_coverage_report(self) -> Dict:
        """
        Generate ATT&CK coverage report.
        
        Returns:
            Dictionary with coverage statistics
        """
        covered_techniques = set()
        covered_tactics = set()
        
        for mapping in self.detection_mappings.values():
            covered_techniques.update(mapping.techniques)
            covered_tactics.update(mapping.tactics)
        
        return {
            'total_techniques': len(self.techniques),
            'covered_techniques': len(covered_techniques),
            'coverage_percentage': (len(covered_techniques) / len(self.techniques) * 100) if self.techniques else 0,
            'total_tactics': len(self.tactics),
            'covered_tactics': len(covered_tactics),
            'detections_count': len(self.detection_mappings),
            'covered_technique_ids': sorted(list(covered_techniques)),
            'covered_tactic_names': sorted(list(covered_tactics))
        }


def main():
    """CLI interface for ATT&CK mapper."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    mapper = AttackMapper()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python mapper.py search <query>         - Search techniques")
        print("  python mapper.py technique <id>          - Get technique details")
        print("  python mapper.py tactic <name>           - List techniques for tactic")
        print("  python mapper.py coverage                - Show coverage report")
        print("  python mapper.py export <path>           - Export mappings to JSON")
        return
    
    command = sys.argv[1]
    
    if command == "search" and len(sys.argv) > 2:
        query = ' '.join(sys.argv[2:])
        results = mapper.search_techniques(query)
        print(f"\nFound {len(results)} techniques matching '{query}':\n")
        for tech in results:
            print(f"{tech.technique_id}: {tech.technique_name}")
            print(f"  Tactics: {', '.join(tech.tactics)}")
            print(f"  Platforms: {', '.join(tech.platforms)}")
            print()
    
    elif command == "technique" and len(sys.argv) > 2:
        tech_id = sys.argv[2].upper()
        technique = mapper.get_technique(tech_id)
        if technique:
            print(f"\n{technique.technique_id}: {technique.technique_name}")
            print(f"Tactics: {', '.join(technique.tactics)}")
            print(f"Platforms: {', '.join(technique.platforms)}")
            print(f"Description: {technique.description[:200]}...")
            if technique.sub_techniques:
                print(f"Sub-techniques: {', '.join(technique.sub_techniques)}")
        else:
            print(f"Technique {tech_id} not found")
    
    elif command == "tactic" and len(sys.argv) > 2:
        tactic = ' '.join(sys.argv[2:])
        techniques = mapper.get_techniques_by_tactic(tactic)
        print(f"\nTechniques for tactic '{tactic}':")
        for tech_id in techniques:
            tech = mapper.get_technique(tech_id)
            if tech:
                print(f"  {tech_id}: {tech.technique_name}")
    
    elif command == "coverage":
        report = mapper.get_coverage_report()
        print("\nATT&CK Coverage Report:")
        print(f"  Detections: {report['detections_count']}")
        print(f"  Covered Techniques: {report['covered_techniques']} / {report['total_techniques']} ({report['coverage_percentage']:.1f}%)")
        print(f"  Covered Tactics: {report['covered_tactics']} / {report['total_tactics']}")
        print(f"\nCovered Techniques: {', '.join(report['covered_technique_ids'])}")
        print(f"Covered Tactics: {', '.join(report['covered_tactic_names'])}")
    
    elif command == "export" and len(sys.argv) > 2:
        output_path = sys.argv[2]
        mapper.export_mappings(output_path)
        print(f"Mappings exported to {output_path}")
    
    else:
        print("Unknown command or missing arguments")


if __name__ == "__main__":
    main()
