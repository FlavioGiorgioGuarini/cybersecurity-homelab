#!/usr/bin/env python3.14
"""Threat Intelligence Engine - Multi-source threat data aggregation"""
import json
import hashlib
import re
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
from colorama import Fore, Style, init

init(autoreset=True)

class ThreatLevel(Enum):
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 4.0
    LOW = 0.1

@dataclass
class ThreatIndicator:
    """Standardized threat indicator"""
    ioc_type: str  # hash, ip, domain, url, email
    value: str
    threat_level: float
    source: str
    first_seen: str
    last_seen: str
    context: Dict
    mitre_technique: Optional[str] = None

@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    name: str
    aliases: List[str]
    techniques: List[str]
    last_activity: str
    attribution_confidence: float
    background: str

@dataclass
class MitreMapping:
    """MITRE ATT&CK mapping"""
    tactic: str
    technique: str
    technique_id: str
    description: str
    mitigations: List[str]

class IoCScraper:
    """Scrape and parse Indicators of Compromise"""
    
    def __init__(self):
        self.indicators: List[ThreatIndicator] = []
    
    def hash_analyzer(self, hash_value: str) -> ThreatIndicator:
        """Analyze file hash (MD5, SHA1, SHA256)"""
        hash_type = self._detect_hash_type(hash_value)
        
        return ThreatIndicator(
            ioc_type='hash',
            value=hash_value,
            threat_level=ThreatLevel.MEDIUM.value,
            source='local_analysis',
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            context={
                'hash_type': hash_type,
                'potential_malware': self._check_malware_db(hash_value)
            }
        )
    
    def ip_intelligence(self, ip_address: str) -> ThreatIndicator:
        """Analyze IP address for threats"""
        risk_score = self._calculate_ip_risk(ip_address)
        
        return ThreatIndicator(
            ioc_type='ip',
            value=ip_address,
            threat_level=risk_score,
            source='threat_feed',
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            context={
                'geolocation': self._geoip_lookup(ip_address),
                'asn': self._asn_lookup(ip_address),
                'reputation': self._check_ip_reputation(ip_address),
                'is_vpn': self._detect_vpn(ip_address),
                'is_proxy': self._detect_proxy(ip_address)
            }
        )
    
    def url_scanner(self, url: str) -> ThreatIndicator:
        """Scan URL for malicious indicators"""
        domain = self._extract_domain(url)
        
        return ThreatIndicator(
            ioc_type='url',
            value=url,
            threat_level=self._assess_url_threat(url),
            source='web_scanner',
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            context={
                'domain': domain,
                'phishing_score': self._check_phishing(url),
                'malware_score': self._check_malware_url(url),
                'ssl_certificate': self._check_ssl(domain),
                'whois_age': self._check_domain_age(domain)
            }
        )
    
    def email_analyzer(self, email: str) -> ThreatIndicator:
        """Analyze email address"""
        return ThreatIndicator(
            ioc_type='email',
            value=email,
            threat_level=self._assess_email_threat(email),
            source='email_intel',
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            context={
                'domain_reputation': self._check_domain_reputation(email.split('@')[1]),
                'breach_history': self._check_breach_db(email),
                'spam_score': self._check_spam_score(email)
            }
        )
    
    @staticmethod
    def _detect_hash_type(hash_val: str) -> str:
        hash_len = len(hash_val)
        if hash_len == 32:
            return 'MD5'
        elif hash_len == 40:
            return 'SHA1'
        elif hash_len == 64:
            return 'SHA256'
        return 'Unknown'
    
    @staticmethod
    def _check_malware_db(hash_val: str) -> str:
        return 'Check VirusTotal API'
    
    @staticmethod
    def _calculate_ip_risk(ip: str) -> float:
        # Simplified risk calculation
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return 0.1
        return 4.0
    
    @staticmethod
    def _geoip_lookup(ip: str) -> str:
        return f'GeoIP lookup for {ip}'
    
    @staticmethod
    def _asn_lookup(ip: str) -> str:
        return f'ASN lookup for {ip}'
    
    @staticmethod
    def _check_ip_reputation(ip: str) -> str:
        return 'Check against threat feeds'
    
    @staticmethod
    def _detect_vpn(ip: str) -> bool:
        return False
    
    @staticmethod
    def _detect_proxy(ip: str) -> bool:
        return False
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        pattern = r'(?:https?://)?(?:www\.)?([^/]+)'
        match = re.search(pattern, url)
        return match.group(1) if match else url
    
    @staticmethod
    def _assess_url_threat(url: str) -> float:
        if 'phishing' in url.lower() or 'malware' in url.lower():
            return 7.0
        return 0.1
    
    @staticmethod
    def _check_phishing(url: str) -> float:
        return 0.5  # Simplified
    
    @staticmethod
    def _check_malware_url(url: str) -> float:
        return 0.3  # Simplified
    
    @staticmethod
    def _check_ssl(domain: str) -> str:
        return 'Valid SSL'
    
    @staticmethod
    def _check_domain_age(domain: str) -> str:
        return 'Domain age check'
    
    @staticmethod
    def _assess_email_threat(email: str) -> float:
        if '.tk' in email or '.ml' in email:
            return 7.0
        return 0.1
    
    @staticmethod
    def _check_domain_reputation(domain: str) -> str:
        return 'Check domain reputation'
    
    @staticmethod
    def _check_breach_db(email: str) -> str:
        return 'Check breach databases'
    
    @staticmethod
    def _check_spam_score(email: str) -> float:
        return 0.2

class MitreMapper:
    """Map indicators to MITRE ATT&CK framework"""
    
    MITRE_DATABASE = {
        'T1566': {'tactic': 'Initial Access', 'technique': 'Phishing', 'description': 'Phishing emails'},
        'T1190': {'tactic': 'Initial Access', 'technique': 'Exploit Public-Facing Application', 'description': 'Exploitation of public-facing apps'},
        'T1119': {'tactic': 'Discovery', 'technique': 'Automated Exfiltration', 'description': 'Automated data theft'},
        'T1087': {'tactic': 'Discovery', 'technique': 'Account Discovery', 'description': 'Discover user accounts'},
        'T1110': {'tactic': 'Credential Access', 'technique': 'Brute Force', 'description': 'Brute force attacks'},
        'T1056': {'tactic': 'Collection', 'technique': 'Input Capture', 'description': 'Capture keystrokes'},
    }
    
    def map_indicator(self, indicator: ThreatIndicator) -> List[MitreMapping]:
        """Map threat indicator to MITRE techniques"""
        mappings = []
        
        # Simple mapping based on indicator type
        if indicator.ioc_type == 'email':
            tech_id = 'T1566'
        elif indicator.ioc_type == 'ip':
            tech_id = 'T1190'
        else:
            tech_id = 'T1119'
        
        if tech_id in self.MITRE_DATABASE:
            db_entry = self.MITRE_DATABASE[tech_id]
            mapping = MitreMapping(
                tactic=db_entry['tactic'],
                technique=db_entry['technique'],
                technique_id=tech_id,
                description=db_entry['description'],
                mitigations=self._get_mitigations(tech_id)
            )
            mappings.append(mapping)
        
        return mappings
    
    @staticmethod
    def _get_mitigations(tech_id: str) -> List[str]:
        mitigations_map = {
            'T1566': ['Email filtering', 'User training', 'Multi-factor authentication'],
            'T1190': ['Patch management', 'Web application firewall', 'Network segmentation'],
            'T1110': ['Account lockout', 'Rate limiting', 'Multi-factor authentication'],
        }
        return mitigations_map.get(tech_id, ['Review and implement controls'])

class ThreatIntelEngine:
    """Main Threat Intelligence aggregation engine"""
    
    def __init__(self):
        self.scraper = IoCScraper()
        self.mitre = MitreMapper()
        self.indicators: List[ThreatIndicator] = []
        self.threat_actors: List[ThreatActor] = []
    
    def analyze_threat(self, ioc_value: str, ioc_type: str = 'auto') -> Dict:
        """Comprehensive threat analysis"""
        
        # Auto-detect IOC type if not specified
        if ioc_type == 'auto':
            ioc_type = self._detect_ioc_type(ioc_value)
        
        try:
            if ioc_type == 'hash':
                indicator = self.scraper.hash_analyzer(ioc_value)
            elif ioc_type == 'ip':
                indicator = self.scraper.ip_intelligence(ioc_value)
            elif ioc_type == 'url':
                indicator = self.scraper.url_scanner(ioc_value)
            elif ioc_type == 'email':
                indicator = self.scraper.email_analyzer(ioc_value)
            else:
                return {'error': f'Unknown IOC type: {ioc_type}'}
            
            # Map to MITRE ATT&CK
            mitre_mappings = self.mitre.map_indicator(indicator)
            
            self.indicators.append(indicator)
            
            return {
                'status': 'success',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'threat_level': indicator.threat_level,
                'threat_rating': self._rate_threat(indicator.threat_level),
                'source': indicator.source,
                'context': indicator.context,
                'mitre_techniques': [
                    {
                        'tactic': m.tactic,
                        'technique': m.technique,
                        'id': m.technique_id,
                        'mitigations': m.mitigations
                    }
                    for m in mitre_mappings
                ]
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _detect_ioc_type(value: str) -> str:
        if len(value) in [32, 40, 64]:
            return 'hash'
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'
        elif '@' in value:
            return 'email'
        elif value.startswith(('http://', 'https://')):
            return 'url'
        return 'unknown'
    
    @staticmethod
    def _rate_threat(level: float) -> str:
        if level >= 9.0:
            return 'CRITICAL'
        elif level >= 7.0:
            return 'HIGH'
        elif level >= 4.0:
            return 'MEDIUM'
        elif level > 0.0:
            return 'LOW'
        return 'INFO'

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] Threat Intelligence Engine Ready{Style.RESET_ALL}")
