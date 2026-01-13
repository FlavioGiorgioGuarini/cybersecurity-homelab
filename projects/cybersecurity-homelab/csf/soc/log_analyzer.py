#!/usr/bin/env python3.14
"""SOC Log Analyzer - IDS/IPS/SIEM Integration"""
import json
import re
from datetime import datetime
from collections import defaultdict
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum
from colorama import Fore, Style, init

init(autoreset=True)

class AlertSeverity(Enum):
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 4.0
    LOW = 0.1
    INFO = 0.0

@dataclass
class SIEMEvent:
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    alert_name: str
    alert_id: int
    severity: float
    raw_log: str
    event_type: str
    metadata: Dict

@dataclass
class CorrelatedIncident:
    incident_id: str
    events: List[SIEMEvent]
    severity: float
    event_count: int
    time_span: float
    attack_pattern: str
    recommendation: str
    confidence_score: float

class IDSParser:
    """Parse IDS/IPS logs from multiple sources"""
    
    SEVERITY_MAP = {1: 9.0, 2: 7.0, 3: 4.0, 4: 0.1}
    
    def __init__(self):
        self.events: List[SIEMEvent] = []
    
    def parse_suricata(self, log_data: str) -> List[SIEMEvent]:
        """Parse Suricata JSON logs"""
        events = []
        for line in log_data.strip().split('\n'):
            try:
                log_entry = json.loads(line)
                if 'alert' in log_entry and 'src_ip' in log_entry:
                    severity = self.SEVERITY_MAP.get(
                        log_entry['alert'].get('signature_id', 0) % 10, 0.1
                    )
                    event = SIEMEvent(
                        timestamp=log_entry.get('timestamp'),
                        source_ip=log_entry.get('src_ip'),
                        dest_ip=log_entry.get('dest_ip'),
                        source_port=log_entry.get('src_port', 0),
                        dest_port=log_entry.get('dest_port', 0),
                        protocol=log_entry.get('proto', 'unknown'),
                        alert_name=log_entry['alert'].get('signature'),
                        alert_id=log_entry['alert'].get('signature_id', 0),
                        severity=severity,
                        raw_log=line,
                        event_type='IDS',
                        metadata=log_entry
                    )
                    events.append(event)
            except json.JSONDecodeError:
                continue
        self.events.extend(events)
        return events
    
    def parse_windows_security(self, log_data: str) -> List[SIEMEvent]:
        """Parse Windows Security Event logs"""
        events = []
        for line in log_data.strip().split('\n'):
            if 'Event ID' in line:
                event = SIEMEvent(
                    timestamp=datetime.now().isoformat(),
                    source_ip='0.0.0.0',
                    dest_ip='0.0.0.0',
                    source_port=0,
                    dest_port=0,
                    protocol='Windows',
                    alert_name='SecurityEvent',
                    alert_id=0,
                    severity=4.0,
                    raw_log=line,
                    event_type='Windows',
                    metadata={'raw': line}
                )
                events.append(event)
        self.events.extend(events)
        return events
    
    def parse_syslog(self, log_data: str) -> List[SIEMEvent]:
        """Parse Linux/Unix syslog entries"""
        events = []
        for line in log_data.strip().split('\n'):
            if 'sudo' in line or 'failed' in line.lower():
                event = SIEMEvent(
                    timestamp=datetime.now().isoformat(),
                    source_ip='0.0.0.0',
                    dest_ip='0.0.0.0',
                    source_port=0,
                    dest_port=0,
                    protocol='Syslog',
                    alert_name='SystemLog',
                    alert_id=hash(line) % 10000,
                    severity=4.0 if 'failed' in line.lower() else 0.1,
                    raw_log=line,
                    event_type='Syslog',
                    metadata={'raw': line}
                )
                events.append(event)
        self.events.extend(events)
        return events

class SIEMCorrelator:
    """Correlate events to identify attack patterns"""
    
    def __init__(self, time_window_seconds: int = 300):
        self.time_window = time_window_seconds
        self.rules = self._init_rules()
    
    def _init_rules(self) -> List[Dict]:
        """Define correlation rules"""
        return [
            {'name': 'Port Scan', 'threshold': 10, 'indicator': 'Multiple ports scanned'},
            {'name': 'DDoS', 'threshold': 100, 'indicator': 'High volume traffic'},
            {'name': 'Brute Force', 'threshold': 5, 'indicator': 'Failed auth attempts'},
            {'name': 'SQL Injection', 'threshold': 1, 'indicator': 'SQL syntax in requests'}
        ]
    
    def correlate(self, events: List[SIEMEvent]) -> List[CorrelatedIncident]:
        """Correlate events to incidents"""
        incidents = []
        for i, event in enumerate(events):
            related = [event]
            for other in events[i+1:]:
                if event.source_ip == other.source_ip:
                    related.append(other)
            if len(related) > 1:
                incidents.append(self._create_incident(related))
        return sorted(incidents, key=lambda x: x.severity, reverse=True)
    
    def _create_incident(self, events: List[SIEMEvent]) -> CorrelatedIncident:
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        avg_severity = sum(e.severity for e in events) / len(events)
        pattern = 'Unknown'
        
        if any('port' in e.alert_name.lower() for e in events):
            pattern = 'Port Scan'
        elif any('login' in e.alert_name.lower() for e in events):
            pattern = 'Brute Force'
        
        return CorrelatedIncident(
            incident_id=incident_id,
            events=events,
            severity=avg_severity,
            event_count=len(events),
            time_span=300,
            attack_pattern=pattern,
            recommendation=f'Investigate {pattern} from {events[0].source_ip}',
            confidence_score=min(len(events) * 0.2, 1.0)
        )

class LogAnalyzer:
    """Main SOC analysis engine"""
    
    def __init__(self):
        self.parser = IDSParser()
        self.correlator = SIEMCorrelator()
        self.incidents: List[CorrelatedIncident] = []
    
    def analyze_logs(self, log_file: str, log_type: str = 'suricata') -> Dict:
        """Analyze security logs"""
        try:
            with open(log_file, 'r') as f:
                log_data = f.read()
            
            if log_type == 'suricata':
                events = self.parser.parse_suricata(log_data)
            elif log_type == 'windows':
                events = self.parser.parse_windows_security(log_data)
            elif log_type == 'syslog':
                events = self.parser.parse_syslog(log_data)
            else:
                return {'error': f'Unknown type: {log_type}'}
            
            incidents = self.correlator.correlate(events)
            self.incidents = incidents
            
            return {
                'status': 'success',
                'total_events': len(events),
                'incidents_detected': len(incidents),
                'critical_count': sum(1 for i in incidents if i.severity >= 9.0),
                'incidents': [
                    {
                        'id': i.incident_id,
                        'severity': i.severity,
                        'pattern': i.attack_pattern,
                        'events': i.event_count,
                        'recommendation': i.recommendation
                    }
                    for i in incidents[:10]
                ]
            }
        except Exception as e:
            return {'error': str(e)}

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] SOC Log Analyzer Ready{Style.RESET_ALL}")
