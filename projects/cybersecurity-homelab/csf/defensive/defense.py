#!/usr/bin/env python3.14
"""Defensive Security & Incident Response"""
import hashlib
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

@dataclass
class Alert:
    alert_id: str
    timestamp: str
    source: str
    severity: float
    alert_type: str
    message: str
    affected_asset: str
    mitigations: List[str]

@dataclass
class FileIntegrity:
    filepath: str
    hash_md5: str
    hash_sha256: str
    size: int
    modified_time: str
    permissions: str
    status: str  # CLEAN, MODIFIED, SUSPICIOUS

class FileIntegrityMonitor:
    """Monitor file integrity"""
    
    def __init__(self):
        self.baseline: Dict[str, FileIntegrity] = {}
        self.changes: List[FileIntegrity] = []
    
    def create_baseline(self, filepath: str) -> FileIntegrity:
        """Create baseline for file"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            file_info = FileIntegrity(
                filepath=filepath,
                hash_md5=hashlib.md5(content).hexdigest(),
                hash_sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                modified_time=datetime.now().isoformat(),
                permissions='644',
                status='CLEAN'
            )
            
            self.baseline[filepath] = file_info
            return file_info
        except Exception as e:
            return None
    
    def verify_integrity(self, filepath: str) -> bool:
        """Verify file hasn't changed"""
        if filepath not in self.baseline:
            return False
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            current_hash = hashlib.sha256(content).hexdigest()
            baseline_hash = self.baseline[filepath].hash_sha256
            
            if current_hash != baseline_hash:
                self.changes.append(FileIntegrity(
                    filepath=filepath,
                    hash_md5=hashlib.md5(content).hexdigest(),
                    hash_sha256=current_hash,
                    size=len(content),
                    modified_time=datetime.now().isoformat(),
                    permissions='644',
                    status='MODIFIED'
                ))
                return False
            
            return True
        except Exception:
            return False

class EndpointHardening:
    """Hardening recommendations for endpoints"""
    
    HARDENING_BASELINE = {
        'firewall': {'status': 'disabled', 'recommendation': 'Enable firewall'},
        'antivirus': {'status': 'not_installed', 'recommendation': 'Install enterprise AV'},
        'mfa': {'status': 'disabled', 'recommendation': 'Enable MFA on all accounts'},
        'disk_encryption': {'status': 'disabled', 'recommendation': 'Enable full disk encryption'},
        'auto_updates': {'status': 'disabled', 'recommendation': 'Enable auto updates'},
        'password_policy': {'status': 'weak', 'recommendation': 'Enforce strong password policy'},
        'audit_logging': {'status': 'disabled', 'recommendation': 'Enable audit logging'},
    }
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    def assess_security_posture(self) -> Dict:
        """Assess endpoint security posture"""
        issues = []
        
        for control, info in self.HARDENING_BASELINE.items():
            if info['status'] != 'enabled':
                issues.append({
                    'control': control,
                    'status': info['status'],
                    'severity': 'HIGH' if control in ['firewall', 'antivirus', 'disk_encryption'] else 'MEDIUM',
                    'remediation': info['recommendation']
                })
        
        return {
            'total_controls': len(self.HARDENING_BASELINE),
            'compliant': len(self.HARDENING_BASELINE) - len(issues),
            'issues': issues,
            'security_score': ((len(self.HARDENING_BASELINE) - len(issues)) / len(self.HARDENING_BASELINE)) * 100
        }

class IncidentResponse:
    """Incident response framework"""
    
    RESPONSE_PLAYBOOKS = {
        'malware_infection': {
            'steps': [
                'Isolate infected system from network',
                'Preserve evidence and memory dump',
                'Identify malware type',
                'Contain threat',
                'Eradicate malware',
                'Restore system from clean backup'
            ],
            'severity': 'CRITICAL'
        },
        'data_breach': {
            'steps': [
                'Identify what data was accessed',
                'Determine user accounts affected',
                'Notify affected users',
                'Monitor for misuse of data',
                'Implement access controls',
                'Conduct post-breach audit'
            ],
            'severity': 'CRITICAL'
        },
        'unauthorized_access': {
            'steps': [
                'Disable compromised accounts',
                'Reset passwords',
                'Check for persistence mechanisms',
                'Review access logs',
                'Implement MFA',
                'Monitor for re-compromise'
            ],
            'severity': 'HIGH'
        },
        'ddos_attack': {
            'steps': [
                'Activate DDoS mitigation',
                'Increase bandwidth capacity',
                'Implement rate limiting',
                'Block malicious IPs',
                'Monitor mitigation effectiveness',
                'Post-incident analysis'
            ],
            'severity': 'HIGH'
        }
    }
    
    def __init__(self):
        self.incidents: List[Alert] = []
    
    def get_playbook(self, incident_type: str) -> Optional[Dict]:
        """Get incident response playbook"""
        return self.RESPONSE_PLAYBOOKS.get(incident_type)
    
    def create_incident(self, incident_type: str, description: str, affected_asset: str) -> Alert:
        """Create incident record"""
        incident = Alert(
            alert_id=f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            source='IncidentResponse',
            severity=9.0 if incident_type == 'malware_infection' else 7.0,
            alert_type=incident_type,
            message=description,
            affected_asset=affected_asset,
            mitigations=self.RESPONSE_PLAYBOOKS.get(incident_type, {}).get('steps', [])
        )
        
        self.incidents.append(incident)
        return incident

class DefenseEngine:
    """Integrated defensive security engine"""
    
    def __init__(self):
        self.fim = FileIntegrityMonitor()
        self.hardening = EndpointHardening()
        self.ir = IncidentResponse()
    
    def run_defense_check(self) -> Dict:
        """Run comprehensive defense check"""
        posture = self.hardening.assess_security_posture()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'security_posture': posture,
            'file_integrity_issues': len(self.fim.changes),
            'active_incidents': len(self.ir.incidents),
            'recommendations': [
                {
                    'priority': 'CRITICAL',
                    'action': 'Enable firewall and antivirus'
                },
                {
                    'priority': 'HIGH',
                    'action': 'Implement MFA and disk encryption'
                },
                {
                    'priority': 'MEDIUM',
                    'action': 'Enable audit logging'
                }
            ]
        }

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] Defense Engine Ready{Style.RESET_ALL}")
