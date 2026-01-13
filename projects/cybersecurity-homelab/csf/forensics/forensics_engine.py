#!/usr/bin/env python3.14
"""Digital Forensics & Evidence Analysis"""
import hashlib
import json
import re
from typing import List, Dict
from dataclasses import dataclass
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

@dataclass
class ForensicArtifact:
    artifact_type: str
    source: str
    data: str
    timestamp: str
    hash_value: str
    evidence_id: str

class LogForensics:
    """Analyze and extract forensic data from logs"""
    
    def __init__(self):
        self.log_entries: List[Dict] = []
        self.suspicious_activities: List[Dict] = []
    
    def parse_auth_logs(self, log_content: str) -> List[Dict]:
        """Parse authentication logs"""
        entries = []
        
        for line in log_content.split('\n'):
            # Detect failed logins
            if 'failed' in line.lower() or 'denied' in line.lower():
                entries.append({
                    'event_type': 'failed_auth',
                    'severity': 'MEDIUM',
                    'raw_log': line,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Detect successful logins
            elif 'accepted' in line.lower() or 'authenticated' in line.lower():
                entries.append({
                    'event_type': 'successful_auth',
                    'severity': 'LOW',
                    'raw_log': line,
                    'timestamp': datetime.now().isoformat()
                })
        
        self.log_entries.extend(entries)
        return entries
    
    def detect_lateral_movement(self, logs: List[Dict]) -> List[Dict]:
        """Detect lateral movement indicators"""
        indicators = []
        
        # Look for multiple failed attempts followed by success
        for i in range(len(logs) - 5):
            failed_count = sum(1 for j in range(i, i + 5) 
                             if logs[j]['event_type'] == 'failed_auth')
            
            if failed_count >= 3:
                indicators.append({
                    'indicator': 'Possible brute force or lateral movement',
                    'severity': 'HIGH',
                    'log_indices': list(range(i, i + 5))
                })
        
        return indicators
    
    def extract_iocs(self, logs: List[Dict]) -> List[Dict]:
        """Extract Indicators of Compromise"""
        iocs = []
        
        for log in logs:
            raw = log.get('raw_log', '')
            
            # Extract IPs
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)
            for ip in ips:
                iocs.append({'type': 'ip', 'value': ip, 'source': 'logs'})
            
            # Extract emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw)
            for email in emails:
                iocs.append({'type': 'email', 'value': email, 'source': 'logs'})
        
        return iocs

class MemoryAnalysis:
    """Analyze memory dumps"""
    
    def __init__(self):
        self.processes: List[Dict] = []
        self.suspicious_strings: List[str] = []
    
    def analyze_memory_dump(self, dump_data: str) -> Dict:
        """Analyze memory dump for indicators"""
        
        # Simulate process detection
        processes = [
            {'pid': 1234, 'name': 'svchost.exe', 'suspicious': False},
            {'pid': 5678, 'name': 'cmd.exe', 'suspicious': True, 'reason': 'Unexpected cmd process'},
            {'pid': 9012, 'name': 'powershell.exe', 'suspicious': True, 'reason': 'Unquoted service path'},
        ]
        
        self.processes = processes
        
        return {
            'total_processes': len(processes),
            'suspicious_processes': sum(1 for p in processes if p.get('suspicious')),
            'processes': processes
        }

class ArtifactCollector:
    """Collect forensic artifacts"""
    
    ARTIFACTS_TO_COLLECT = [
        'Windows Registry',
        'Event Logs',
        'Browser History',
        'Temporary Files',
        'Prefetch Files',
        'MFT (Master File Table)',
        'Swap/Page Files',
        'Recycle Bin'
    ]
    
    def __init__(self):
        self.collected_artifacts: List[ForensicArtifact] = []
    
    def collect_artifacts(self) -> Dict:
        """Collect forensic artifacts"""
        collected = []
        
        for artifact in self.ARTIFACTS_TO_COLLECT:
            evidence = ForensicArtifact(
                artifact_type=artifact,
                source='System',
                data=f'Evidence from {artifact}',
                timestamp=datetime.now().isoformat(),
                hash_value=hashlib.sha256(artifact.encode()).hexdigest(),
                evidence_id=f"EV-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
            
            self.collected_artifacts.append(evidence)
            collected.append({
                'artifact': artifact,
                'evidence_id': evidence.evidence_id,
                'hash': evidence.hash_value[:16] + '...'
            })
        
        return {
            'total_artifacts': len(collected),
            'artifacts': collected
        }

class ForensicsEngine:
    """Integrated digital forensics engine"""
    
    def __init__(self):
        self.log_forensics = LogForensics()
        self.memory_analysis = MemoryAnalysis()
        self.artifact_collector = ArtifactCollector()
        self.findings: List[Dict] = []
    
    def run_forensic_investigation(self, log_content: str) -> Dict:
        """Run complete forensic investigation"""
        
        # Parse logs
        logs = self.log_forensics.parse_auth_logs(log_content)
        
        # Detect lateral movement
        lateral_movement = self.log_forensics.detect_lateral_movement(logs)
        
        # Extract IOCs
        iocs = self.log_forensics.extract_iocs(logs)
        
        # Analyze memory
        memory_analysis = self.memory_analysis.analyze_memory_dump('')
        
        # Collect artifacts
        artifacts = self.artifact_collector.collect_artifacts()
        
        return {
            'investigation_id': f"INVEST-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'log_entries_parsed': len(logs),
            'lateral_movement_indicators': len(lateral_movement),
            'iocs_extracted': len(iocs),
            'suspicious_processes': memory_analysis['suspicious_processes'],
            'artifacts_collected': artifacts['total_artifacts'],
            'summary': {
                'critical_findings': lateral_movement,
                'iocs': iocs[:10],
                'suspicious_processes': memory_analysis['processes']
            }
        }

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] Forensics Engine Ready{Style.RESET_ALL}")
