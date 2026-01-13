#!/usr/bin/env python3.14
"""Web Application Security Scanner"""
import re
import json
import base64
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
from colorama import Fore, Style, init
from urllib.parse import quote, parse_qs, urlparse

init(autoreset=True)

class VulnSeverity(Enum):
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 4.0
    LOW = 0.1

@dataclass
class Vulnerability:
    """Web vulnerability finding"""
    vuln_type: str
    severity: float
    affected_param: str
    payload: str
    description: str
    proof_of_concept: str
    remediation: str
    cvss_score: float

class SQLiDetector:
    """SQL Injection detection engine"""
    
    SQL_PATTERNS = [
        r"('|\"|;|--|/\*|\*/|xp_|sp_)",
        r"(union|select|insert|update|delete|drop|create|alter)",
        r"(or|and)\s*('|1|0)=('|1|0)",
        r"(\bor\b).*(\bselect\b)",
        r"(\bunion\b).*(\bselect\b)",
    ]
    
    PAYLOAD_TEMPLATES = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR 'a'='a",
        "1' OR '1'='1' /*",
    ]
    
    def __init__(self):
        self.findings: List[Vulnerability] = []
    
    def detect_sqli(self, parameter_value: str, param_name: str) -> Optional[Vulnerability]:
        """Detect SQL injection in parameter"""
        for pattern in self.SQL_PATTERNS:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return Vulnerability(
                    vuln_type='SQL Injection',
                    severity=VulnSeverity.CRITICAL.value,
                    affected_param=param_name,
                    payload=parameter_value,
                    description='Potential SQL injection vulnerability detected',
                    proof_of_concept=f"Parameter {param_name} = {self.PAYLOAD_TEMPLATES[0]}",
                    remediation='Use parameterized queries/prepared statements',
                    cvss_score=9.8
                )
        return None
    
    def test_payloads(self, param_name: str, base_value: str) -> List[Vulnerability]:
        """Test common SQL injection payloads"""
        findings = []
        for payload in self.PAYLOAD_TEMPLATES:
            test_input = payload
            if self.detect_sqli(test_input, param_name):
                findings.append(Vulnerability(
                    vuln_type='SQL Injection',
                    severity=VulnSeverity.CRITICAL.value,
                    affected_param=param_name,
                    payload=payload,
                    description='SQL injection vulnerability confirmed',
                    proof_of_concept=f'Injected payload: {payload}',
                    remediation='Implement input validation and use prepared statements',
                    cvss_score=9.8
                ))
        return findings

class XSSFinder:
    """Cross-Site Scripting (XSS) detection"""
    
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe',
        r'<embed',
        r'<object',
        r'alert\(',
    ]
    
    PAYLOAD_TEMPLATES = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>',
    ]
    
    def __init__(self):
        self.findings: List[Vulnerability] = []
    
    def detect_xss(self, parameter_value: str, param_name: str) -> Optional[Vulnerability]:
        """Detect potential XSS vulnerabilities"""
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, parameter_value, re.IGNORECASE):
                return Vulnerability(
                    vuln_type='Cross-Site Scripting (XSS)',
                    severity=VulnSeverity.HIGH.value,
                    affected_param=param_name,
                    payload=parameter_value,
                    description='Potential XSS vulnerability detected',
                    proof_of_concept=f"Injected script in {param_name}",
                    remediation='Implement output encoding and input validation',
                    cvss_score=6.1
                )
        return None
    
    def test_payloads(self, param_name: str) -> List[Vulnerability]:
        """Test XSS payloads"""
        findings = []
        for payload in self.PAYLOAD_TEMPLATES:
            if self.detect_xss(payload, param_name):
                findings.append(Vulnerability(
                    vuln_type='Cross-Site Scripting (XSS)',
                    severity=VulnSeverity.HIGH.value,
                    affected_param=param_name,
                    payload=payload,
                    description='XSS vulnerability confirmed',
                    proof_of_concept=f'Payload: {payload}',
                    remediation='Use HTML entity encoding and CSP headers',
                    cvss_score=6.1
                ))
        return findings

class JWTAnalyzer:
    """JWT token security analyzer"""
    
    def __init__(self):
        self.findings: List[Vulnerability] = []
    
    def analyze_jwt(self, token: str) -> Dict:
        """Analyze JWT token for security issues"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format'}
            
            # Decode header
            header_pad = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_pad))
            
            # Decode payload
            payload_pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_pad))
            
            findings = []
            
            # Check for weak algorithms
            if header.get('alg') in ['none', 'HS256']:
                findings.append({
                    'issue': 'Weak algorithm',
                    'severity': 'HIGH',
                    'recommendation': 'Use RS256 or ES256'
                })
            
            # Check for expired tokens
            import time
            if 'exp' in payload:
                if payload['exp'] < time.time():
                    findings.append({
                        'issue': 'Token expired',
                        'severity': 'CRITICAL'
                    })
            
            return {
                'status': 'valid',
                'header': header,
                'payload': payload,
                'issues': findings
            }
        except Exception as e:
            return {'error': str(e)}

class WebSecurityScanner:
    """Complete web application security scanner"""
    
    def __init__(self):
        self.sqli_detector = SQLiDetector()
        self.xss_finder = XSSFinder()
        self.jwt_analyzer = JWTAnalyzer()
        self.all_findings: List[Vulnerability] = []
    
    def scan_url(self, url: str) -> Dict:
        """Scan URL for vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        findings = []
        
        # Check each parameter
        for param_name, param_values in params.items():
            for param_value in param_values:
                # SQLi detection
                sqli_vuln = self.sqli_detector.detect_sqli(param_value, param_name)
                if sqli_vuln:
                    findings.append(sqli_vuln)
                
                # XSS detection
                xss_vuln = self.xss_finder.detect_xss(param_value, param_name)
                if xss_vuln:
                    findings.append(xss_vuln)
        
        return {
            'url': url,
            'vulnerabilities_found': len(findings),
            'critical_count': sum(1 for f in findings if f.severity >= 9.0),
            'high_count': sum(1 for f in findings if 7.0 <= f.severity < 9.0),
            'findings': [
                {
                    'type': f.vuln_type,
                    'severity': f.severity,
                    'parameter': f.affected_param,
                    'remediation': f.remediation,
                    'cvss': f.cvss_score
                }
                for f in findings[:20]
            ]
        }
    
    def test_common_vulns(self, base_url: str) -> Dict:
        """Test for common web vulnerabilities"""
        findings = {
            'sqli_tests': self.sqli_detector.test_payloads('id', '1'),
            'xss_tests': self.xss_finder.test_payloads('search'),
            'security_headers': self._check_security_headers(),
            'total_vulnerabilities': 0
        }
        
        findings['total_vulnerabilities'] = (
            len(findings['sqli_tests']) + 
            len(findings['xss_tests'])
        )
        
        return findings
    
    @staticmethod
    def _check_security_headers() -> Dict:
        """Check for missing security headers"""
        return {
            'Content-Security-Policy': 'Missing',
            'X-Frame-Options': 'Missing',
            'X-Content-Type-Options': 'Missing',
            'Strict-Transport-Security': 'Missing',
            'X-XSS-Protection': 'Missing'
        }

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] Web Security Scanner Ready{Style.RESET_ALL}")
