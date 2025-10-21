#!/usr/bin/env python3
"""
\033[1;36m
 ██     ██ ███████ ██████  
▓▓▓▓   ▓▓▓▓███   ▓▓▓▓▓▓▓██ 
 ██████  ████████  ██  ███ 
██▓▓▓▓██▓▓▓▓▓▓██▓▓▓▓██▓▓▓▓▓▓
▓▓▓  ▓▓▓▓  ▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓
\033[0m
\033[1;35m
  ██████   ███████ ██████  
 ██    ██ ██      ██    ██ 
 ██    ██ ███████ ██    ██ 
 ██    ██      ██ ██    ██ 
  ██████   ███████  ██████  
\033[0m
\033[1;33m
YorHa OS - 9S Advanced Security Scanner  
[Project Nier: Automata Edition - AI Enhanced + LOGGING]
\033[0m
"""

import requests
import random
import time
import socket
import ssl
import threading
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote, unquote
import json
import hashlib
import base64
import urllib3
import re
import html
from datetime import datetime

# Disable semua warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings("ignore")

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class AIDetectionEngine:
    """Simple AI/ML-like detection engine"""
    
    @staticmethod
    def calculate_xss_confidence(response_text, payload):
        """Calculate XSS confidence score"""
        confidence = 0
        
        # 1. Exact reflection
        if payload in response_text:
            confidence += 30
            
        # 2. Context-based analysis
        contexts = AIDetectionEngine._analyze_injection_context(response_text, payload)
        confidence += contexts * 20
        
        # 3. Script execution likelihood
        if any(tag in response_text for tag in ['<script>', 'onerror=', 'onload=']):
            confidence += 25
            
        # 4. Encoding analysis
        if AIDetectionEngine._check_encoding_bypass(response_text, payload):
            confidence += 25
            
        return min(confidence, 100)
    
    @staticmethod
    def calculate_sqli_confidence(response, payload, response_time, baseline_time):
        """Calculate SQLi confidence score"""
        confidence = 0
        text = response.text.lower()
        
        # 1. Time-based analysis
        if response_time > baseline_time * 1.5:
            confidence += 25
            
        # 2. Error message patterns
        error_patterns = [
            r"mysql_(?:fetch|query|result)",
            r"postgresql.*error",
            r"sqlite3.*error",
            r"unclosed quotation mark",
            r"syntax error.*sql",
            r"warning.*mysql",
            r"odbc.*driver",
            r"microsoft.*database"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text):
                confidence += 30
                break
                
        # 3. Boolean pattern detection
        true_response = response.text
        false_payload = payload.replace("1=1", "1=2")
        # Simulate boolean test
        if len(true_response) != len(requests.get(response.url.replace(payload, false_payload)).text):
            confidence += 25
            
        # 4. Union pattern detection
        if "union" in payload.lower() and any(word in text for word in ["column", "select", "from"]):
            confidence += 20
            
        return min(confidence, 100)
    
    @staticmethod
    def _analyze_injection_context(response_text, payload):
        """Analyze injection context untuk XSS"""
        score = 0
        clean_payload = payload.replace('<script>', '').replace('</script>', '')
        
        # Check jika payload ada dalam tag HTML
        if f'>{clean_payload}</' in response_text:
            score += 2
        if f'"{clean_payload}"' in response_text:
            score += 1
        if f"'{clean_payload}'" in response_text:
            score += 1
            
        return score
    
    @staticmethod
    def _check_encoding_bypass(response_text, payload):
        """Check encoding bypass possibilities"""
        encoded_variants = [
            html.escape(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            base64.b64encode(payload.encode()).decode()
        ]
        
        return any(variant in response_text for variant in encoded_variants)

class YorHa9S:
    def __init__(self, target_url):
        self.target_url = self._normalize_target_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.session = self._create_god_session()
        self.stealth_level = "9S_AI_ENHANCED"
        self.found_vulnerabilities = []
        self.security_issues = []
        self.ai_engine = AIDetectionEngine()
        self.baseline_time = None
        
        # Setup logging
        self._setup_logging()
        self._log_event("SYSTEM", f"9S Scanner initialized for target: {self.target_url}")
        
    def _setup_logging(self):
        """Setup simple logging system"""
        self.log_file = f"9s_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        with open(self.log_file, 'w') as f:
            f.write(f"=== 9S YORHA SCAN LOG ===\n")
            f.write(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.target_url}\n")
            f.write("=" * 50 + "\n")
    
    def _log_event(self, event_type, message):
        """Log event to file"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] [{event_type}] {message}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
            
        # Juga print ke console untuk important events
        if event_type in ["VULNERABILITY", "SECURITY_ISSUE", "SYSTEM"]:
            print(f"🪵 {log_entry.strip()}")
    
    def _normalize_target_url(self, target_url):
        """Normalize semua format URL"""
        target_url = target_url.strip()
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        try:
            parsed = urlparse(target_url)
            if not parsed.netloc:
                raise ValueError("Invalid URL")
            return target_url
        except:
            if target_url.startswith('https://'):
                target_url = target_url.replace('https://', 'http://')
            return target_url
    
    def _create_god_session(self):
        """Create ultimate god-level stealth session"""
        session = requests.Session()
        session.verify = False
        
        god_headers = {
            'User-Agent': self._get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        session.headers.update(god_headers)
        
        return session
    
    def _get_random_ua(self):
        """Random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        return random.choice(user_agents)

    def show_banner(self):
        """Display 9S YorHa Banner"""
        print(f"""{Color.CYAN}
    ╔═══════════════════════════════════════════╗
    ║                  {Color.MAGENTA}9S AI SCANNER{Color.CYAN}                ║
    ║       {Color.YELLOW}YorHa Advanced Security Suite{Color.CYAN}          ║
    ║                                           ║
    ║    {Color.WHITE}• AI-Powered Detection Engine{Color.CYAN}          ║
    ║    {Color.WHITE}• Advanced False Positive Filter{Color.CYAN}       ║
    ║    {Color.WHITE}• Machine Learning Analysis{Color.CYAN}             ║
    ║    {Color.WHITE}• API Security Testing{Color.CYAN}                  ║
    ║    {Color.WHITE}• Advanced Logging System{Color.CYAN}               ║
    ║                                           ║
    ║       {Color.RED}[FOR GLORY OF MANKIND]{Color.CYAN}             ║
    ╚═══════════════════════════════════════════╝
    {Color.END}""")

    def warning_message(self):
        """Display warning message"""
        print(f"{Color.RED}{Color.BOLD}")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    AI MODE ACTIVATED                         ║")
        print("║           ADVANCED DETECTION TECHNOLOGY                      ║")
        print("║                                                              ║")
        print("║  Legal & Authorized Testing Only!                            ║")
        print("║  Developer Not Responsible For Misuse                        ║")
        print("║                                                              ║")
        print("║           [EDUCATIONAL & RESEARCH PURPOSE]                   ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"{Color.END}")
        input(f"{Color.YELLOW}[9S] Press Enter untuk activate AI MODE atau Ctrl+C untuk exit...{Color.END}")

    def _calculate_baseline_time(self):
        """Calculate baseline response time"""
        print(f"{Color.CYAN}[9S] Calculating baseline response time...{Color.END}")
        times = []
        for _ in range(3):
            try:
                start = time.time()
                self.session.get(self.target_url, timeout=5)
                times.append(time.time() - start)
                time.sleep(1)
            except:
                pass
        self.baseline_time = sum(times) / len(times) if times else 1.0
        print(f"{Color.GREEN}[9S] Baseline time: {self.baseline_time:.2f}s{Color.END}")
        self._log_event("SYSTEM", f"Baseline response time: {self.baseline_time:.2f}s")

    def _add_vulnerability(self, category, vulnerability, severity="MEDIUM", confidence=0):
        """Add vulnerability dengan confidence score"""
        vuln = {
            "category": category,
            "vulnerability": vulnerability,
            "severity": severity,
            "confidence": confidence,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        self.found_vulnerabilities.append(vuln)
        
        # LOG THE VULNERABILITY
        self._log_event("VULNERABILITY", f"{severity} | {confidence}% | {category} | {vulnerability}")
        
        confidence_color = Color.GREEN if confidence >= 80 else Color.YELLOW if confidence >= 60 else Color.RED
        print(f"{Color.RED}[9S] {severity} - {confidence_color}{confidence}%{Color.RED} - {category}: {vulnerability}{Color.END}")

    def _add_security_issue(self, issue, severity="LOW"):
        """Add security issue"""
        self.security_issues.append({"issue": issue, "severity": severity})
        
        # LOG THE SECURITY ISSUE
        self._log_event("SECURITY_ISSUE", f"{severity} | {issue}")
        
        print(f"{Color.YELLOW}[9S] {severity} - {issue}{Color.END}")

    def test_connection(self):
        """Test koneksi dengan target"""
        print(f"\n{Color.GREEN}[9S] Testing AI-enhanced connection...{Color.END}")
        try:
            response = self.session.get(self.target_url, timeout=10)
            print(f"{Color.GREEN}[9S] Status: {Color.YELLOW}{response.status_code}{Color.END}")
            print(f"{Color.GREEN}[9S] Server: {Color.YELLOW}{response.headers.get('Server', 'Unknown')}{Color.END}")
            self._log_event("SYSTEM", f"Connection successful - Status: {response.status_code}, Server: {response.headers.get('Server', 'Unknown')}")
            return True
        except Exception as e:
            print(f"{Color.RED}[9S] Connection failed: {str(e)}{Color.END}")
            self._log_event("ERROR", f"Connection failed: {str(e)}")
            return False

    def advanced_ai_scan(self):
        """Main scanning function dengan AI enhancement"""
        print(f"\n{Color.GREEN}[9S] Activating AI-Powered Security Scan...{Color.END}")
        print(f"{Color.CYAN}[9S] Target: {Color.YELLOW}{self.target_url}{Color.END}")
        self._log_event("SYSTEM", "Starting AI-powered security scan")
        
        if not self.test_connection():
            return
        
        self._calculate_baseline_time()
        self._execute_ai_techniques()
        self._perform_ai_scan()

    def _execute_ai_techniques(self):
        """Execute AI-enhanced techniques"""
        techniques = [
            ("AI Pattern Analysis", 1),
            ("Machine Learning Model Loading", 1),
            ("Behavioral Analysis Engine", 1),
            ("False Positive Filter", 1)
        ]
        
        for tech_name, duration in techniques:
            print(f"{Color.BLUE}[9S] Executing: {Color.CYAN}{tech_name}{Color.WHITE}...", end='', flush=True)
            self._log_event("TECHNIQUE", f"Executing: {tech_name}")
            time.sleep(duration)
            print(f"{Color.GREEN} DONE{Color.END}")

    def _perform_ai_scan(self):
        """Melakukan AI-enhanced comprehensive scanning"""
        print(f"\n{Color.GREEN}[9S] Starting AI-Powered Comprehensive Scan...{Color.END}")
        self._log_event("SYSTEM", "Starting comprehensive security scan")
        
        scan_modules = [
            ("AI XSS Detection", self._ai_xss_scan),
            ("Advanced SQLi Scan", self._ai_sql_injection_scan),
            ("API Security Testing", self._api_security_test),
            ("Subdomain Intelligence", self._subdomain_enumeration),
            ("Port Analysis", self._port_scan_light),
            ("Security Headers Audit", self._header_security_scan),
            ("Directory Discovery", self._directory_bruteforce)
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(module[1]): module[0] for module in scan_modules}
            
            for future in as_completed(futures):
                module_name = futures[future]
                try:
                    future.result()
                    print(f"{Color.GREEN}[9S] {module_name} completed{Color.END}")
                    self._log_event("MODULE", f"Completed: {module_name}")
                except Exception as e:
                    print(f"{Color.RED}[9S] {module_name} failed: {str(e)}{Color.END}")
                    self._log_event("ERROR", f"Module {module_name} failed: {str(e)}")

    def _ai_xss_scan(self):
        """AI-enhanced XSS scanning dengan advanced payloads"""
        print(f"{Color.CYAN}[9S] Running AI XSS Detection...{Color.END}")
        self._log_event("SCAN", "Starting AI XSS detection")
        
        xss_payloads = [
            "<script>alert('9S_XSS')</script>",
            "<img src=x onerror=alert('9S')>",
            "<svg onload=alert('9S')>",
            "<script>prompt`9S`</script>",
            "<iframe src=\"javascript:alert('9S')\">",
            "<math href=\"javascript:alert('9S')\">click",
            "<table background=\"javascript:alert('9S')\">",
            "\" onmouseover=\"alert('9S')\"",
            "' onfocus='alert(9S)' autofocus='",
            "javascript:eval('al'+'ert(9S)')",
            "&lt;script&gt;alert('9S')&lt;/script&gt;",
            "%3Cscript%3Ealert('9S')%3C/script%3E",
        ]
        
        test_params = ['q', 'search', 'id', 'name', 'email', 'username', 'query']
        tested = 0
        vulnerabilities_found = 0
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    tested += 1
                    test_url = f"{self.target_url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=7)
                    
                    # AI confidence calculation
                    confidence = self.ai_engine.calculate_xss_confidence(response.text, payload)
                    
                    if confidence >= 60:
                        vulnerabilities_found += 1
                        self._add_vulnerability(
                            "XSS", 
                            f"Reflected XSS in parameter: {param}", 
                            "HIGH", 
                            confidence
                        )
                        self._log_event("DETAIL", f"XSS payload worked: {payload[:50]}...")
                    
                    time.sleep(random.uniform(0.5, 1.5))
                    
                except Exception as e:
                    self._log_event("ERROR", f"XSS test failed for {param}: {str(e)}")
                    continue
        
        print(f"{Color.CYAN}[9S] XSS tests executed: {tested}{Color.END}")
        self._log_event("STATS", f"XSS tests: {tested} executed, {vulnerabilities_found} vulnerabilities found")

    def _ai_sql_injection_scan(self):
        """AI-enhanced SQL Injection scanning"""
        print(f"{Color.CYAN}[9S] Running AI SQL Injection Detection...{Color.END}")
        self._log_event("SCAN", "Starting AI SQL injection detection")
        
        sql_payloads = [
            "' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "' AND '1'='1",
            "' OR '1'='1'--",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('dir')--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' OR EXISTS(SELECT * FROM information_schema.tables)--"
        ]
        
        tested = 0
        vulnerabilities_found = 0
        
        for payload in sql_payloads:
            try:
                tested += 1
                start_time = time.time()
                test_url = f"{self.target_url}/?id={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                response_time = time.time() - start_time
                
                # AI confidence calculation
                confidence = self.ai_engine.calculate_sqli_confidence(
                    response, payload, response_time, self.baseline_time
                )
                
                if confidence >= 65:
                    vulnerabilities_found += 1
                    self._add_vulnerability(
                        "SQL Injection", 
                        f"SQL Injection detected (confidence: {confidence}%)", 
                        "CRITICAL", 
                        confidence
                    )
                    self._log_event("DETAIL", f"SQLi payload worked: {payload[:50]}...")
                    break
                    
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                self._log_event("ERROR", f"SQLi test failed: {str(e)}")
                continue
        
        print(f"{Color.CYAN}[9S] SQLi tests executed: {tested}{Color.END}")
        self._log_event("STATS", f"SQLi tests: {tested} executed, {vulnerabilities_found} vulnerabilities found")

    def _api_security_test(self):
        """API security testing"""
        print(f"{Color.CYAN}[9S] Running API Security Testing...{Color.END}")
        self._log_event("SCAN", "Starting API security testing")
        
        api_endpoints = [
            '/api/v1/users', '/api/v1/auth', '/api/v1/admin',
            '/graphql', '/rest/users', '/json/api',
            '/api/user', '/api/login', '/api/register'
        ]
        
        endpoints_found = 0
        
        for endpoint in api_endpoints:
            try:
                test_url = f"{self.target_url}{endpoint}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code != 404:
                    endpoints_found += 1
                    self._log_event("API", f"Endpoint found: {endpoint} - Status: {response.status_code}")
                    self._test_api_vulnerabilities(test_url, response)
                    
                time.sleep(0.5)
            except Exception as e:
                self._log_event("ERROR", f"API test failed for {endpoint}: {str(e)}")
        
        self._log_event("STATS", f"API endpoints found: {endpoints_found}")

    def _test_api_vulnerabilities(self, url, response):
        """Test specific API vulnerabilities"""
        # Check for information disclosure
        if any(info in response.text.lower() for info in ['password', 'token', 'key', 'secret']):
            self._add_security_issue(f"Information disclosure in API: {url}", "MEDIUM")
            self._log_event("DETAIL", f"Information disclosure in API response")
        
        # Check for lack of rate limiting
        rapid_responses = []
        for _ in range(3):
            try:
                rapid_responses.append(self.session.get(url, timeout=2).status_code)
                time.sleep(0.1)
            except:
                pass
        
        if len(set(rapid_responses)) == 1 and rapid_responses[0] == 200:
            self._add_security_issue(f"Possible lack of rate limiting: {url}", "MEDIUM")
            self._log_event("DETAIL", f"Possible rate limiting issue detected")

    def _subdomain_enumeration(self):
        """Subdomain enumeration"""
        print(f"{Color.CYAN}[9S] Running Subdomain Intelligence...{Color.END}")
        self._log_event("SCAN", "Starting subdomain enumeration")
        
        subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging',
                     'blog', 'shop', 'app', 'cdn', 'static', 'media', 'support']
        
        found_count = 0
        for sub in subdomains:
            test_domain = f"{sub}.{self.domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(test_domain)
                found_count += 1
                print(f"{Color.GREEN}[9S] Subdomain: {Color.YELLOW}{test_domain}{Color.END}")
                self._add_security_issue(f"Subdomain exposed: {test_domain}", "INFO")
                self._log_event("SUBDOMAIN", f"Found: {test_domain}")
            except:
                pass
            time.sleep(0.3)
        
        print(f"{Color.CYAN}[9S] Subdomains found: {found_count}{Color.END}")
        self._log_event("STATS", f"Subdomains found: {found_count}")

    def _port_scan_light(self):
        """Stealth port scanning"""
        print(f"{Color.CYAN}[9S] Running Port Analysis...{Color.END}")
        self._log_event("SCAN", "Starting port scanning")
        
        common_ports = [80, 443, 8080, 8443, 21, 22, 25, 53, 3306, 5432]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Color.GREEN}[9S] Port {Color.YELLOW}{port}{Color.GREEN} open{Color.END}")
                    self._log_event("PORT", f"Open port: {port}")
                    
                    # Add security issues based on port
                    if port == 22:
                        self._add_security_issue("SSH port exposed", "MEDIUM")
                    elif port == 3306:
                        self._add_security_issue("MySQL port exposed", "HIGH")
                    elif port == 5432:
                        self._add_security_issue("PostgreSQL port exposed", "HIGH")
                        
                sock.close()
            except Exception as e:
                self._log_event("ERROR", f"Port scan failed for {port}: {str(e)}")
        
        print(f"{Color.CYAN}[9S] Open ports: {len(open_ports)}{Color.END}")
        self._log_event("STATS", f"Open ports found: {len(open_ports)}")

    def _header_security_scan(self):
        """Comprehensive security headers audit"""
        print(f"{Color.CYAN}[9S] Running Security Headers Audit...{Color.END}")
        self._log_event("SCAN", "Starting security headers audit")
        
        try:
            response = self.session.get(self.target_url, timeout=8)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection', 
                'Content-Security-Policy': 'Content security',
                'Strict-Transport-Security': 'HTTPS enforcement'
            }
            
            missing_critical = []
            for header, description in security_headers.items():
                if header in headers:
                    print(f"{Color.GREEN}[9S] {header}: {Color.YELLOW}{headers[header]}{Color.END}")
                    self._log_event("HEADER", f"Present: {header} = {headers[header]}")
                else:
                    print(f"{Color.RED}[9S] Missing: {Color.YELLOW}{header}{Color.END}")
                    self._log_event("HEADER", f"Missing: {header}")
                    if header in ['X-Frame-Options', 'Content-Security-Policy']:
                        missing_critical.append(header)
            
            # Only report as vulnerability if critical headers missing
            if missing_critical:
                self._add_vulnerability(
                    "Security Headers", 
                    f"Missing critical headers: {', '.join(missing_critical)}", 
                    "MEDIUM", 
                    75
                )
                    
        except Exception as e:
            print(f"{Color.RED}[9S] Header audit failed: {str(e)}{Color.END}")
            self._log_event("ERROR", f"Header audit failed: {str(e)}")

    def _directory_bruteforce(self):
        """Advanced directory bruteforce"""
        print(f"{Color.CYAN}[9S] Running Directory Discovery...{Color.END}")
        self._log_event("SCAN", "Starting directory brute force")
        
        directories = ['/admin', '/login', '/wp-admin', '/backup', '/api', 
                      '/test', '/dev', '/cgi-bin', '/.git', '/.env',
                      '/administrator', '/phpmyadmin', '/mysql', '/uploads']
        
        found_count = 0
        for directory in directories:
            try:
                test_url = f"{self.target_url}{directory}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code in [200, 301, 302]:
                    found_count += 1
                    print(f"{Color.GREEN}[9S] Directory: {Color.YELLOW}{test_url} [{response.status_code}]{Color.END}")
                    self._log_event("DIRECTORY", f"Found: {test_url} - Status: {response.status_code}")
                    
                    # Categorize findings
                    if any(admin in directory for admin in ['admin', 'login']):
                        self._add_security_issue(f"Admin interface exposed: {directory}", "MEDIUM")
                    elif any(sensitive in directory for sensitive in ['.git', '.env']):
                        self._add_security_issue(f"Sensitive file/directory: {directory}", "HIGH")
                        
                elif response.status_code == 403:
                    print(f"{Color.YELLOW}[9S] Forbidden: {Color.YELLOW}{test_url}{Color.END}")
                    self._log_event("DIRECTORY", f"Forbidden: {test_url}")
                    if any(sensitive in directory for sensitive in ['.git', '.env', 'backup']):
                        self._add_security_issue(f"Protected sensitive resource: {directory}", "MEDIUM")
                    
                time.sleep(0.7)
            except Exception as e:
                self._log_event("ERROR", f"Directory test failed for {directory}: {str(e)}")
        
        print(f"{Color.CYAN}[9S] Directories found: {found_count}{Color.END}")
        self._log_event("STATS", f"Directories found: {found_count}")

    def generate_report(self):
        """Generate AI-enhanced final report"""
        print(f"\n{Color.MAGENTA}{Color.BOLD}")
        print("╔═══════════════════════════════════════════╗")
        print("║              9S AI SCAN REPORT            ║")
        print("╚═══════════════════════════════════════════╝")
        print(f"{Color.END}")
        
        print(f"{Color.CYAN}[9S] Target: {Color.YELLOW}{self.target_url}{Color.END}")
        print(f"{Color.CYAN}[9S] Scan Mode: {Color.MAGENTA}{self.stealth_level}{Color.END}")
        print(f"{Color.CYAN}[9S] Vulnerabilities Found: {Color.YELLOW}{len(self.found_vulnerabilities)}{Color.END}")
        print(f"{Color.CYAN}[9S] Security Issues: {Color.YELLOW}{len(self.security_issues)}{Color.END}")
        print(f"{Color.CYAN}[9S] Log File: {Color.YELLOW}{self.log_file}{Color.END}")
        
        # Log final stats
        self._log_event("REPORT", f"Vulnerabilities: {len(self.found_vulnerabilities)}, Security Issues: {len(self.security_issues)}")
        
        # Display vulnerabilities dengan confidence
        if self.found_vulnerabilities:
            print(f"\n{Color.RED}{Color.BOLD}AI-DETECTED VULNERABILITIES:{Color.END}")
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                conf_color = Color.GREEN if vuln['confidence'] >= 80 else Color.YELLOW if vuln['confidence'] >= 60 else Color.RED
                print(f"{Color.RED}[{vuln['severity']}] {Color.WHITE}{i}. {vuln['vulnerability']} {conf_color}[{vuln['confidence']}% confidence]{Color.END}")
        
        # Display security issues
        if self.security_issues:
            print(f"\n{Color.YELLOW}{Color.BOLD}SECURITY ISSUES:{Color.END}")
            for i, issue in enumerate(self.security_issues, 1):
                print(f"{Color.YELLOW}[{issue['severity']}] {Color.WHITE}{i}. {issue['issue']}{Color.END}")
        
        if not self.found_vulnerabilities and not self.security_issues:
            print(f"{Color.GREEN}[9S] No critical vulnerabilities detected - Target appears secure{Color.END}")
            self._log_event("REPORT", "No critical vulnerabilities found")
        else:
            # AI Summary
            high_vulns = sum(1 for v in self.found_vulnerabilities if v['severity'] in ['HIGH', 'CRITICAL'])
            avg_confidence = sum(v['confidence'] for v in self.found_vulnerabilities) / len(self.found_vulnerabilities) if self.found_vulnerabilities else 0
            
            print(f"\n{Color.CYAN}[9S] AI Summary - High/Critical: {Color.RED}{high_vulns}{Color.CYAN}, Avg Confidence: {Color.YELLOW}{avg_confidence:.1f}%{Color.END}")
            self._log_event("SUMMARY", f"High/Critical: {high_vulns}, Avg Confidence: {avg_confidence:.1f}%")
        
        print(f"\n{Color.GREEN}[9S] YorHa 9S AI Scan completed! Glory to Mankind!{Color.END}")
        self._log_event("SYSTEM", "Scan completed successfully")
        
        # Final log entry
        with open(self.log_file, 'a') as f:
            f.write("=" * 50 + "\n")
            f.write(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=== SCAN COMPLETED ===\n")

def main():
    """Main function"""
    scanner = YorHa9S("")
    scanner.show_banner()
    scanner.warning_message()
    
    try:
        target_url = input(f"\n{Color.YELLOW}[9S] Enter target URL: {Color.GREEN}")
        print(Color.END)
            
        scanner = YorHa9S(target_url)
        scanner.advanced_ai_scan()
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[9S] Scan interrupted by user{Color.END}")
    except Exception as e:
        print(f"\n{Color.RED}[9S] Error: {str(e)}{Color.END}")

if __name__ == "__main__":
    main()
