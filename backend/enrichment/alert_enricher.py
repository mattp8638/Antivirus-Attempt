import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from attack.mapper import AttackMapper
from intel.ioc_matcher import IOCMatcher, IOCMatch

logger = logging.getLogger(__name__)


class AlertEnricher:
    """
    Enriches security alerts with contextual intelligence.
    
    Combines ATT&CK framework mapping with threat intelligence
    to provide comprehensive alert context.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize alert enricher.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Initialize ATT&CK mapper
        attack_matrix_path = config.get('attack', {}).get('matrix_path',
                                                           '/var/tamsilcms/attack/enterprise-attack.json')
        self.attack_mapper = AttackMapper(attack_matrix_path)
        
        # Initialize IOC matcher
        ioc_feed_path = config.get('threat_intel', {}).get('feed_path',
                                                            '/var/tamsilcms/intel/iocs.json')
        self.ioc_matcher = IOCMatcher(ioc_feed_path)
        
        logger.info("Alert enricher initialized")
    
    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich an alert with all available intelligence.
        
        Args:
            alert: Raw alert dictionary
            
        Returns:
            Enriched alert with ATT&CK and threat intel context
        """
        enriched = alert.copy()
        
        # Add ATT&CK context
        enriched = self.attack_mapper.enrich_alert(enriched)
        
        # Add threat intelligence context
        enriched = self._add_threat_intel(enriched)
        
        # Adjust severity based on enrichment
        enriched = self._adjust_severity(enriched)
        
        # Generate recommendations
        enriched = self._add_recommendations(enriched)
        
        # Add enrichment metadata
        enriched['enrichment'] = {
            'enriched_at': datetime.utcnow().isoformat() + "Z",
            'version': '1.0',
            'sources': ['attack', 'threat_intel']
        }
        
        return enriched
    
    def _add_threat_intel(self, alert: Dict) -> Dict:
        """
        Add threat intelligence context to alert.
        
        Args:
            alert: Alert to enrich
            
        Returns:
            Alert with threat intel context
        """
        # Extract telemetry from alert
        telemetry = alert.get('telemetry', {})
        if not telemetry:
            # Try to construct telemetry from alert fields
            telemetry = self._extract_telemetry_from_alert(alert)
        
        # Match against IOCs
        ioc_matches = self.ioc_matcher.match_telemetry(telemetry)
        
        if not ioc_matches:
            return alert
        
        # Build threat intel context
        threat_intel = {
            'ioc_matches': [],
            'threat_actors': set(),
            'campaigns': set(),
            'max_confidence': 0.0,
            'max_severity': 'low'
        }
        
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        
        for match in ioc_matches:
            ioc = match.ioc
            
            # Add match details
            threat_intel['ioc_matches'].append({
                'type': ioc.ioc_type,
                'value': match.matched_value,
                'threat_actor': ioc.threat_actor,
                'campaign': ioc.campaign,
                'confidence': ioc.confidence,
                'severity': ioc.severity,
                'description': ioc.description,
                'tags': ioc.tags
            })
            
            # Track actors and campaigns
            if ioc.threat_actor:
                threat_intel['threat_actors'].add(ioc.threat_actor)
            if ioc.campaign:
                threat_intel['campaigns'].add(ioc.campaign)
            
            # Track max confidence and severity
            threat_intel['max_confidence'] = max(threat_intel['max_confidence'], ioc.confidence)
            if severity_order[ioc.severity] > severity_order[threat_intel['max_severity']]:
                threat_intel['max_severity'] = ioc.severity
        
        # Convert sets to lists for JSON serialization
        threat_intel['threat_actors'] = list(threat_intel['threat_actors'])
        threat_intel['campaigns'] = list(threat_intel['campaigns'])
        threat_intel['match_count'] = len(ioc_matches)
        
        alert['threat_intel'] = threat_intel
        
        return alert
    
    def _extract_telemetry_from_alert(self, alert: Dict) -> Dict:
        """
        Extract telemetry structure from alert fields.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Telemetry dictionary
        """
        telemetry = {}
        
        # Extract network indicators
        network_fields = ['remote_ip', 'dst_ip', 'source_ip', 'destination_ip', 
                         'domain', 'hostname', 'dns_query']
        network_data = {}
        for field in network_fields:
            if field in alert:
                network_data[field] = alert[field]
        if network_data:
            telemetry['network'] = network_data
        
        # Extract file indicators
        file_fields = ['md5', 'sha1', 'sha256', 'hash', 'file_path', 'file_name']
        file_data = {}
        for field in file_fields:
            if field in alert:
                file_data[field] = alert[field]
        if file_data:
            telemetry['file'] = file_data
        
        # Extract process indicators
        process_fields = ['process_name', 'process_path', 'command_line', 'parent_process']
        process_data = {}
        for field in process_fields:
            if field in alert:
                process_data[field] = alert[field]
        # Add process hashes if available
        for hash_field in ['process_md5', 'process_sha256']:
            if hash_field in alert:
                hash_type = hash_field.replace('process_', '')
                process_data[hash_type] = alert[hash_field]
        if process_data:
            telemetry['process'] = process_data
        
        # Extract registry indicators
        if 'registry_path' in alert or 'registry_key' in alert:
            telemetry['registry'] = {
                'path': alert.get('registry_path') or alert.get('registry_key')
            }
        
        return telemetry
    
    def _adjust_severity(self, alert: Dict) -> Dict:
        """
        Adjust alert severity based on enrichment context.
        
        Args:
            alert: Enriched alert
            
        Returns:
            Alert with adjusted severity
        """
        original_severity = alert.get('severity', 'medium')
        adjusted_severity = original_severity
        adjustment_reasons = []
        
        # Check threat intel matches
        if 'threat_intel' in alert:
            ti = alert['threat_intel']
            
            # High-confidence IOC matches increase severity
            if ti.get('max_confidence', 0) >= 0.8:
                if ti['max_severity'] == 'critical':
                    adjusted_severity = 'critical'
                    adjustment_reasons.append("Critical IOC match with high confidence")
                elif ti['max_severity'] == 'high' and adjusted_severity != 'critical':
                    adjusted_severity = 'high'
                    adjustment_reasons.append("High-severity IOC match")
            
            # Known threat actor increases severity
            if ti.get('threat_actors'):
                actors = ', '.join(ti['threat_actors'])
                adjustment_reasons.append(f"Associated with threat actor(s): {actors}")
                if adjusted_severity == 'medium':
                    adjusted_severity = 'high'
        
        # Check ATT&CK context
        if 'attack' in alert:
            attack_ctx = alert['attack']
            
            # Impact tactics are high severity
            if 'Impact' in attack_ctx.get('tactics', []):
                if adjusted_severity not in ['critical', 'high']:
                    adjusted_severity = 'high'
                    adjustment_reasons.append("ATT&CK Impact tactic detected")
            
            # High confidence detection
            if attack_ctx.get('confidence', 0) >= 0.9:
                adjustment_reasons.append("High-confidence ATT&CK mapping")
        
        # Store adjustment info
        if adjusted_severity != original_severity:
            alert['severity_adjustment'] = {
                'original': original_severity,
                'adjusted': adjusted_severity,
                'reasons': adjustment_reasons
            }
            alert['severity'] = adjusted_severity
        
        return alert
    
    def _add_recommendations(self, alert: Dict) -> Dict:
        """
        Generate response recommendations based on alert context.
        
        Args:
            alert: Enriched alert
            
        Returns:
            Alert with recommendations
        """
        recommendations = []
        
        # Check for threat intel matches
        if 'threat_intel' in alert and alert['threat_intel'].get('match_count', 0) > 0:
            ti = alert['threat_intel']
            
            if ti['threat_actors']:
                actors = ', '.join(ti['threat_actors'])
                recommendations.append({
                    'priority': 'high',
                    'action': 'investigate',
                    'description': f"Investigate connection to known threat actor(s): {actors}",
                    'reason': 'threat_actor_match'
                })
            
            # IOC-specific recommendations
            for ioc_match in ti.get('ioc_matches', []):
                if ioc_match['type'] == 'ip':
                    recommendations.append({
                        'priority': 'high',
                        'action': 'block',
                        'description': f"Block malicious IP: {ioc_match['value']}",
                        'reason': 'malicious_ip',
                        'target': ioc_match['value']
                    })
                elif ioc_match['type'] == 'domain':
                    recommendations.append({
                        'priority': 'high',
                        'action': 'block',
                        'description': f"Block malicious domain: {ioc_match['value']}",
                        'reason': 'malicious_domain',
                        'target': ioc_match['value']
                    })
                elif ioc_match['type'] == 'hash':
                    recommendations.append({
                        'priority': 'critical',
                        'action': 'quarantine',
                        'description': f"Quarantine file with malicious hash: {ioc_match['value']}",
                        'reason': 'malicious_file',
                        'target': ioc_match['value']
                    })
        
        # ATT&CK-based recommendations
        if 'attack' in alert:
            attack_ctx = alert['attack']
            
            for technique in attack_ctx.get('techniques', []):
                tech_id = technique['id']
                
                # Ransomware (T1486)
                if tech_id == 'T1486':
                    recommendations.append({
                        'priority': 'critical',
                        'action': 'isolate',
                        'description': "Isolate endpoint immediately to prevent ransomware spread",
                        'reason': 'ransomware_detected'
                    })
                    recommendations.append({
                        'priority': 'high',
                        'action': 'backup_check',
                        'description': "Verify backup integrity and recoverability",
                        'reason': 'ransomware_detected'
                    })
                
                # Credential dumping (T1003)
                elif tech_id.startswith('T1003'):
                    recommendations.append({
                        'priority': 'high',
                        'action': 'reset_credentials',
                        'description': "Reset credentials for affected user accounts",
                        'reason': 'credential_theft'
                    })
                    recommendations.append({
                        'priority': 'medium',
                        'action': 'audit',
                        'description': "Audit recent authentication events for compromised credentials",
                        'reason': 'credential_theft'
                    })
                
                # Defense evasion (T1562)
                elif tech_id == 'T1562':
                    recommendations.append({
                        'priority': 'high',
                        'action': 'restore_defenses',
                        'description': "Re-enable disabled security controls",
                        'reason': 'defense_evasion'
                    })
        
        # General recommendations based on severity
        severity = alert.get('severity', 'medium')
        if severity == 'critical':
            recommendations.append({
                'priority': 'critical',
                'action': 'escalate',
                'description': "Escalate to security team immediately",
                'reason': 'critical_severity'
            })
        
        if recommendations:
            alert['recommendations'] = recommendations
        
        return alert
    
    def batch_enrich(self, alerts: List[Dict]) -> List[Dict]:
        """
        Enrich multiple alerts in batch.
        
        Args:
            alerts: List of alerts to enrich
            
        Returns:
            List of enriched alerts
        """
        enriched_alerts = []
        
        for alert in alerts:
            try:
                enriched = self.enrich_alert(alert)
                enriched_alerts.append(enriched)
            except Exception as e:
                logger.error(f"Failed to enrich alert {alert.get('id', 'unknown')}: {e}")
                # Return original alert on error
                enriched_alerts.append(alert)
        
        return enriched_alerts
    
    def get_enrichment_stats(self) -> Dict:
        """
        Get enrichment statistics.
        
        Returns:
            Statistics dictionary
        """
        attack_coverage = self.attack_mapper.get_coverage_report()
        ioc_stats = self.ioc_matcher.get_statistics()
        
        return {
            'attack_coverage': attack_coverage,
            'ioc_statistics': ioc_stats,
            'enrichment_sources': ['attack', 'threat_intel']
        }


def main():
    """CLI interface for alert enricher."""
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Load config
    config = {
        'attack': {
            'matrix_path': '/var/tamsilcms/attack/enterprise-attack.json'
        },
        'threat_intel': {
            'feed_path': '/var/tamsilcms/intel/iocs.json'
        }
    }
    
    enricher = AlertEnricher(config)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python alert_enricher.py enrich <alert_json>   - Enrich an alert")
        print("  python alert_enricher.py stats                 - Show enrichment stats")
        print("  python alert_enricher.py test                  - Run test enrichment")
        return
    
    command = sys.argv[1]
    
    if command == "enrich" and len(sys.argv) > 2:
        alert_json = sys.argv[2]
        
        try:
            # Parse alert JSON
            if alert_json.startswith('{'):
                alert = json.loads(alert_json)
            else:
                # Treat as file path
                with open(alert_json, 'r') as f:
                    alert = json.load(f)
            
            # Enrich
            enriched = enricher.enrich_alert(alert)
            
            # Output
            print(json.dumps(enriched, indent=2))
            
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif command == "stats":
        stats = enricher.get_enrichment_stats()
        print("\nEnrichment Statistics:\n")
        
        print("ATT&CK Coverage:")
        print(f"  Detections: {stats['attack_coverage']['detections_count']}")
        print(f"  Covered Techniques: {stats['attack_coverage']['covered_techniques']}")
        print(f"  Coverage: {stats['attack_coverage']['coverage_percentage']:.1f}%")
        
        print("\nThreat Intelligence:")
        print(f"  Total IOCs: {stats['ioc_statistics']['total']}")
        print(f"  Threat Actors: {len(stats['ioc_statistics']['threat_actors'])}")
        print(f"  Campaigns: {len(stats['ioc_statistics']['campaigns'])}")
    
    elif command == "test":
        # Test alert
        test_alert = {
            'id': 'test-001',
            'type': 'ransomware_file_encryption',
            'severity': 'high',
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'host': 'workstation-42',
            'user': 'john.doe',
            'description': 'Ransomware encryption activity detected',
            'indicators': {
                'high_volume_modifications': 150,
                'suspicious_extensions': ['.encrypted', '.locked']
            }
        }
        
        print("\nTest Alert (Before Enrichment):")
        print(json.dumps(test_alert, indent=2))
        
        enriched = enricher.enrich_alert(test_alert)
        
        print("\nTest Alert (After Enrichment):")
        print(json.dumps(enriched, indent=2))
    
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()
