import requests
from concurrent.futures import ThreadPoolExecutor
import ssl
import socket

class VulnerabilityScanner:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.vulnerabilities = []

    def scan(self):
        self.logger.info("Starting vulnerability scan...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self._check_ssl)
            executor.submit(self._check_xss)
            executor.submit(self._check_sqli)
            executor.submit(self._check_open_dirs)
        
        return self.vulnerabilities

    def _check_ssl(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    # Check certificate expiration and other details
                    self.logger.info("SSL certificate verified")
        except Exception as e:
            self.vulnerabilities.append({
                'type': 'SSL',
                'description': f'SSL vulnerability found: {str(e)}',
                'severity': 'High'
            })

    def _check_xss(self):
        test_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
        
        for payload in test_payloads:
            try:
                r = requests.get(f"http://{self.target}", params={'test': payload})
                if payload in r.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'description': 'Potential XSS vulnerability found',
                        'severity': 'High',
                        'payload': payload
                    })
            except Exception as e:
                self.logger.error(f"XSS check failed: {str(e)}")

    def _check_sqli(self):
        test_payloads = ["' OR '1'='1", "1' OR '1'='1"]
        
        for payload in test_payloads:
            try:
                r = requests.get(f"http://{self.target}", params={'id': payload})
                if 'error' in r.text.lower() or 'mysql' in r.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'description': 'Potential SQL injection vulnerability found',
                        'severity': 'Critical',
                        'payload': payload
                    })
            except Exception as e:
                self.logger.error(f"SQLi check failed: {str(e)}")

    def _check_open_dirs(self):
        common_dirs = ['/admin', '/backup', '/config', '/db', '/logs']
        
        for directory in common_dirs:
            try:
                r = requests.get(f"http://{self.target}{directory}")
                if r.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Open Directory',
                        'description': f'Potentially sensitive directory found: {directory}',
                        'severity': 'Medium',
                        'path': directory
                    })
            except Exception as e:
                self.logger.error(f"Directory check failed: {str(e)}")
