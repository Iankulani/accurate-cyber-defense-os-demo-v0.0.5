#!/usr/bin/env python3
"""
ACCURATE ONLINE OS DEMO - ENHANCED VERSION WITH ADVANCED NMAP
Author: Ian Carter Kulani
Version: Demo v3.0
Python Version
"""

import os
import sys
import json
import sqlite3
import subprocess
import socket
import ipaddress
import re
import time
import datetime
import threading
import signal
import platform
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import shutil

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. Install with: pip install psutil")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests not available. Install with: pip install requests")

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("Warning: geoip2 not available. Install with: pip install geoip2")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: whois not available. Install with: pip install python-whois")

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"

# Ensure directories exist
Path(REPORT_DIR).mkdir(exist_ok=True)
Path(SCAN_RESULTS_DIR).mkdir(exist_ok=True)

# Nmap scan types
NMAP_SCAN_TYPES = {
    'quick': '-T4 -F',
    'stealth': '-sS -T2',
    'comprehensive': '-sS -sV -sC -A -O',
    'udp': '-sU',
    'vulnerability': '-sV --script vuln',
    'full': '-p- -sV -sC -A -O'
}


@dataclass
class ScanResult:
    scan_id: str
    success: bool
    target: str
    scan_type: str
    cmd: str
    execution_time: float
    result: Dict
    vulnerabilities: List[Dict]
    raw_output: str
    timestamp: str


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None


@dataclass
class Vulnerability:
    port: int
    issues: List[str]


class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if len(name) > 255:
            return False
        
        if name.endswith('.'):
            name = name[:-1]
        
        allowed = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", re.IGNORECASE)
        return allowed.match(name) is not None
    
    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        if platform.system() == 'Windows':
            return ['tracert', '-d', target]
        return ['traceroute', '-n', '-q', '1', '-w', '2', target]
    
    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Dict[str, Any]:
        """Run subprocess and capture output"""
        output_lines = []
        start_time = time.time()
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Read output in real-time
            while True:
                output = proc.stdout.readline()
                if output == '' and proc.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    output_lines.append(line)
                    print(line)
            
            # Get any remaining output
            stdout, stderr = proc.communicate()
            if stdout:
                output_lines.extend(stdout.strip().split('\n'))
            if stderr:
                output_lines.extend(stderr.strip().split('\n'))
            
            returncode = proc.returncode
            
        except Exception as e:
            error_msg = f"[!] Error running command: {str(e)}"
            print(error_msg)
            output_lines.append(error_msg)
            returncode = -2
        
        execution_time = time.time() - start_time
        
        return {
            'returncode': returncode,
            'output': '\n'.join(output_lines),
            'execution_time': execution_time
        }
    
    async def interactive_traceroute(self, target: str = None) -> str:
        """Interactive traceroute with target input"""
        if not target:
            target = await self.prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"
        
        try:
            cmd = self.choose_traceroute_cmd(target)
        except Exception as e:
            return f"❌ Traceroute error: {str(e)}"
        
        print(f"Running: {' '.join(cmd)}\n")
        result = self.stream_subprocess(cmd)
        
        output = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        output += f"Command: <code>{' '.join(cmd)}</code>\n"
        output += f"Execution time: {result['execution_time']:.2f}s\n"
        output += f"Return code: {result['returncode']}\n\n"
        
        if len(result['output']) > 3000:
            output += f"<code>{result['output'][-3000:]}</code>"
        else:
            output += f"<code>{result['output']}</code>"
        
        return output
    
    async def prompt_target(self) -> Optional[str]:
        """Prompt user for target input"""
        print('\n' + '='*50)
        print("🌐 Traceroute Tool")
        print('='*50)
        
        while True:
            try:
                user_input = input("\nEnter target IP address or hostname (or 'quit' to exit): ").strip()
                
                if not user_input:
                    print("Please enter a non-empty value.")
                    continue
                
                if user_input.lower() in ['q', 'quit', 'exit']:
                    return None
                
                if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                    return user_input
                else:
                    print("Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return None
            except Exception as e:
                print(f"Error: {str(e)}")
                return None


class DatabaseManager:
    """SQLite database manager for storing scan results and logs"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        tables = [
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_output TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS network_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_cidr TEXT NOT NULL,
                discovered_hosts TEXT,
                scan_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        
        for table_sql in tables:
            cursor.execute(table_sql)
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command execution"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)",
            (command, source, 1 if success else 0)
        )
        
        conn.commit()
        conn.close()
    
    def save_scan_result(self, scan_id: str, target: str, scan_type: str,
                        open_ports: List[Dict], services: List[Dict],
                        os_info: str, vulnerabilities: List[Dict], raw_output: str):
        """Save scan result to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO scan_results 
            (scan_id, target, scan_type, open_ports, services, os_info, vulnerabilities, raw_output) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, target, scan_type, json.dumps(open_ports), json.dumps(services),
             os_info, json.dumps(vulnerabilities), raw_output)
        )
        
        conn.commit()
        conn.close()
    
    def get_scan_results(self, limit: int = 20) -> List[Dict]:
        """Get recent scan results"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT scan_id, target, scan_type, timestamp FROM scan_results ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_scan_details(self, scan_id: str) -> Optional[Dict]:
        """Get detailed scan information"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM scan_results WHERE scan_id = ?",
            (scan_id,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log security threat"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)",
            (ip_address, threat_type, severity, description)
        )
        
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent security threats"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip_address FROM monitored_ips WHERE is_active = 1")
        results = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        return results
    
    def add_monitored_ip(self, ip: str):
        """Add IP to monitoring list"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR REPLACE INTO monitored_ips (ip_address, is_active) VALUES (?, 1)",
            (ip,)
        )
        
        conn.commit()
        conn.close()
    
    def remove_monitored_ip(self, ip: str):
        """Remove IP from monitoring list"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE monitored_ips SET is_active = 0 WHERE ip_address = ?",
            (ip,)
        )
        
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 100) -> List[Dict]:
        """Get command history"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM command_history ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results


class NetworkScanner:
    """Basic network scanning utilities"""
    
    def __init__(self):
        self.traceroute_tool = TracerouteTool()
    
    def ping_ip(self, ip: str) -> str:
        """Ping an IP address"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'
            
            result = subprocess.run(
                ['ping', param, count, ip],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                return f"Ping {ip}: successful\n{result.stdout}"
            else:
                return f"Ping {ip}: failed\n{result.stderr}"
                
        except subprocess.TimeoutExpired:
            return f"Ping {ip}: timeout"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    async def traceroute(self, target: str) -> str:
        """Perform traceroute"""
        return await self.traceroute_tool.interactive_traceroute(target)
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP geolocation information"""
        try:
            # Try using ip-api.com (free service)
            if REQUESTS_AVAILABLE:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        location_info = {
                            'ip': ip,
                            'country': data.get('country', 'N/A'),
                            'region': data.get('regionName', 'N/A'),
                            'city': data.get('city', 'N/A'),
                            'isp': data.get('isp', 'N/A'),
                            'org': data.get('org', 'N/A'),
                            'lat': data.get('lat', 'N/A'),
                            'lon': data.get('lon', 'N/A'),
                            'timezone': data.get('timezone', 'N/A')
                        }
                        return json.dumps(location_info, indent=2)
            
            # Fallback to socket DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return json.dumps({'ip': ip, 'hostname': hostname}, indent=2)
            except:
                return json.dumps({'ip': ip, 'error': 'Location lookup failed'}, indent=2)
                
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def whois_lookup(self, domain: str) -> str:
        """Perform WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return "WHOIS not available. Install with: pip install python-whois"
        
        try:
            result = whois.whois(domain)
            return str(result)
        except Exception as e:
            return f"WHOIS error: {str(e)}"
    
    def dns_lookup(self, domain: str) -> str:
        """Perform DNS lookup"""
        try:
            # A records
            a_records = []
            try:
                a_records = socket.gethostbyname_ex(domain)[2]
            except:
                pass
            
            result = {
                'domain': domain,
                'a_records': a_records,
                'mx_records': 'MX lookup requires additional libraries',
                'txt_records': 'TXT lookup requires additional libraries'
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            return f"DNS lookup error: {str(e)}"


class AdvancedNetworkScanner:
    """Advanced network scanning with Nmap integration"""
    
    def __init__(self):
        self.base_scanner = NetworkScanner()
        self.nmap_available = self.check_nmap_installation()
    
    def check_nmap_installation(self) -> bool:
        """Check if Nmap is installed and accessible"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"✅ Nmap is installed: {result.stdout[:100]}")
                return True
            else:
                print("⚠️ Nmap is not installed or not in PATH")
                return False
                
        except Exception as e:
            print(f"⚠️ Nmap check failed: {str(e)}")
            return False
    
    def execute_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute shell command and capture output"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for long scans
            )
            
            execution_time = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr,
                'execution_time': execution_time,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': 'Command timed out after 5 minutes',
                'execution_time': execution_time,
                'return_code': -1
            }
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': f'Error: {str(e)}',
                'execution_time': execution_time,
                'return_code': -2
            }
    
    def perform_nmap_scan(self, target: str, scan_type: str, options: Dict = None) -> ScanResult:
        """Perform Nmap scan with specified type"""
        import uuid
        import hashlib
        
        scan_id = hashlib.md5(f"{target}{scan_type}{time.time()}".encode()).hexdigest()[:16]
        scan_options = NMAP_SCAN_TYPES.get(scan_type, scan_type)
        
        # Build command
        cmd = ['nmap', target] + scan_options.split()
        
        if options and 'ports' in options:
            # Remove -F if present and add custom ports
            if '-F' in cmd:
                cmd.remove('-F')
            cmd.extend(['-p', options['ports']])
        
        print(f"Running Nmap scan: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = self.execute_command(cmd)
            
            parsed_result = self.parse_nmap_output(result['output'])
            vulnerabilities = self.analyze_vulnerabilities(parsed_result)
            
            return ScanResult(
                scan_id=scan_id,
                success=result['success'],
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=result['execution_time'],
                result=parsed_result,
                vulnerabilities=vulnerabilities,
                raw_output=result['output'][:5000],
                timestamp=datetime.datetime.now().isoformat()
            )
            
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                success=False,
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=time.time() - start_time,
                result={},
                vulnerabilities=[],
                raw_output=f'Error: {str(e)}',
                timestamp=datetime.datetime.now().isoformat()
            )
    
    def parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data"""
        lines = output.split('\n')
        result = {
            'host': '',
            'status': '',
            'addresses': [],
            'ports': [],
            'os': '',
            'services': []
        }
        
        current_port = None
        
        for line in lines:
            # Parse Nmap report header
            if 'Nmap scan report for' in line:
                result['host'] = line.replace('Nmap scan report for', '').strip()
            elif 'Host is up' in line:
                result['status'] = 'up'
            elif 'Host seems down' in line:
                result['status'] = 'down'
            elif re.match(r'^\d+/(tcp|udp)\s+(open|closed|filtered)', line):
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_parts = parts[0].split('/')
                    current_port = {
                        'port': int(port_parts[0]),
                        'protocol': port_parts[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    result['ports'].append(current_port)
            elif 'Service Info:' in line:
                result['os'] = line.replace('Service Info:', '').strip()
            elif current_port and line.strip().startswith('|'):
                # Service version info
                current_port['version'] = line.strip()[1:].strip()
        
        return result
    
    def analyze_vulnerabilities(self, scan_result: Dict) -> List[Dict]:
        """Analyze scan results for potential vulnerabilities"""
        vulnerabilities = []
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900]
        weak_services = ['telnet', 'ftp', 'smtp', 'pop3', 'imap', 'vnc']
        
        for port_info in scan_result.get('ports', []):
            vuln = {'port': port_info['port'], 'issues': []}
            
            # Check for critical ports
            if port_info['port'] in critical_ports and port_info['state'] == 'open':
                vuln['issues'].append(f"Critical port {port_info['port']} is open")
            
            # Check for weak services
            if any(weak in port_info['service'].lower() for weak in weak_services):
                vuln['issues'].append(f"Weak service {port_info['service']} detected")
            
            # Check for default credentials services
            if 'http' in port_info['service'].lower() or 'web' in port_info['service'].lower():
                vuln['issues'].append("Web service detected - check for default credentials")
            
            if vuln['issues']:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def network_discovery(self, network_range: str) -> Dict[str, Any]:
        """Discover hosts in network range"""
        cmd = ['nmap', '-sn', network_range]
        
        try:
            result = self.execute_command(cmd)
            
            if not result['success']:
                return {'success': False, 'error': result['output']}
            
            lines = result['output'].split('\n')
            hosts = []
            
            for line in lines:
                ip_match = re.search(r'Nmap scan report for (?:[a-zA-Z0-9.-]+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
            
            return {
                'success': True,
                'network': network_range,
                'hosts': hosts,
                'count': len(hosts),
                'execution_time': result['execution_time'],
                'raw_output': result['output']
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def stealth_scan(self, target: str) -> Dict[str, Any]:
        """Perform stealth SYN scan"""
        cmd = ['nmap', '-sS', '-T2', '-f', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'stealth',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """Perform OS detection"""
        cmd = ['nmap', '-O', '--osscan-guess', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'os_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def service_detection(self, target: str) -> Dict[str, Any]:
        """Perform service version detection"""
        cmd = ['nmap', '-sV', '--version-intensity', '5', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'service_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def save_scan_to_file(self, scan_result: ScanResult, filename: str) -> str:
        """Save scan result to file"""
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        with open(filepath, 'w') as f:
            json.dump(asdict(scan_result), f, indent=2, default=str)
        
        return str(filepath)


class TelegramBotHandler:
    """Telegram bot handler for remote commands"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.advanced_scanner = AdvancedNetworkScanner()
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict:
        """Setup command handler functions"""
        return {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping_ip': self.handle_ping_ip,
            '/tracert_ip': self.handle_tracert_ip,
            '/nmap_scan': self.handle_nmap_scan,
            '/nmap_discovery': self.handle_network_discovery,
            '/nmap_stealth': self.handle_stealth_scan,
            '/nmap_os': self.handle_os_detection,
            '/nmap_services': self.handle_service_detection,
            '/scan_history': self.handle_scan_history,
            '/scan_details': self.handle_scan_details,
            '/save_scan': self.handle_save_scan,
            '/vulnerability_scan': self.handle_vulnerability_scan,
            '/full_scan': self.handle_full_scan,
            '/quick_scan': self.handle_quick_scan,
            '/port_scan': self.handle_port_scan,
            '/network_map': self.handle_network_map,
            '/whois': self.handle_whois,
            '/dns_lookup': self.handle_dns_lookup,
            '/analyze_ip': self.handle_analyze_ip,
            '/status': self.handle_status,
            '/system_info': self.handle_system_info,
            '/threat_summary': self.handle_threat_summary,
            '/generate_report': self.handle_generate_report,
            '/custom_scan': self.handle_custom_scan,
            '/compare_scans': self.handle_compare_scans,
            '/nmap_advanced': self.handle_nmap_advanced
        }
    
    async def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message via Telegram bot"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
        
        if not REQUESTS_AVAILABLE:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4096] for i in range(0, len(message), 4096)]
                for msg in messages:
                    payload = {
                        'chat_id': self.monitor.telegram_chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    
                    response = requests.post(url, json=payload, timeout=30)
                    if response.status_code != 200:
                        return False
                    
                    time.sleep(0.5)
                
                return True
            else:
                payload = {
                    'chat_id': self.monitor.telegram_chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                
                response = requests.post(url, json=payload, timeout=30)
                return response.status_code == 200
                
        except Exception as e:
            print(f"Telegram send error: {str(e)}")
            return False
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>Accurate Online OS v3.0 - Advanced Edition</b> 🚀

🔍 <b>Advanced Nmap Commands:</b>
/nmap_scan [IP] [type] - Perform Nmap scan
/nmap_advanced [IP] - Advanced options
/nmap_discovery [network] - Network discovery
/nmap_stealth [IP] - Stealth scan
/nmap_os [IP] - OS detection
/nmap_services [IP] - Service detection
/vulnerability_scan [IP] - Vulnerability scan
/full_scan [IP] - Full port scan
/quick_scan [IP] - Quick scan
/custom_scan [IP] [options] - Custom scan
/port_scan [IP] [ports] - Port scan

📊 <b>Scan Management:</b>
/scan_history - View scan history
/scan_details [id] - View scan details
/save_scan [id] - Save scan to file
/compare_scans [id1] [id2] - Compare scans
/network_map [range] - Create network map

🌐 <b>Basic Tools:</b>
/ping_ip [IP] - Ping IP address
/tracert_ip [IP] - Traceroute
/whois [domain] - WHOIS lookup
/dns_lookup [domain] - DNS lookup
/analyze_ip [IP] - Analyze IP

💻 <b>System Commands:</b>
/status - System status
/system_info - System information
/threat_summary - Recent threats
/generate_report - Generate report

❓ Type /help for detailed usage!
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        return """
<b>🔒 Complete Command Reference</b>

<b>🔍 Advanced Nmap Scanning:</b>
<code>/nmap_scan 192.168.1.1 quick</code>
<code>/nmap_scan 192.168.1.1 comprehensive</code>
<code>/nmap_stealth 10.0.0.1</code>
<code>/nmap_os 192.168.1.1</code>
<code>/vulnerability_scan 192.168.1.1</code>
<code>/full_scan 192.168.1.1</code>
<code>/port_scan 192.168.1.1 80,443,22</code>
<code>/network_map 192.168.1.0/24</code>

<b>📊 Scan Management:</b>
<code>/scan_history</code>
<code>/scan_details abc123</code>
<code>/save_scan abc123</code>

<b>🌐 Network Tools:</b>
<code>/ping_ip 8.8.8.8</code>
<code>/tracert_ip google.com</code>
<code>/whois example.com</code>
<code>/dns_lookup example.com</code>
<code>/analyze_ip 1.1.1.1</code>

<b>💻 System:</b>
<code>/status</code>
<code>/system_info</code>
<code>/threat_summary</code>
<code>/generate_report</code>
        """
    
    async def handle_nmap_scan(self, args: List[str]) -> str:
        """Handle /nmap_scan command"""
        if len(args) < 2:
            return "❌ Usage: <code>/nmap_scan [IP] [type]</code>\nAvailable types: quick, stealth, comprehensive, udp, vulnerability, full"
        
        target = args[0]
        scan_type = args[1]
        
        if scan_type not in NMAP_SCAN_TYPES:
            return f"❌ Invalid scan type. Available: {', '.join(NMAP_SCAN_TYPES.keys())}"
        
        await self.send_telegram_message(f"🔍 Starting {scan_type} scan on {target}...")
        
        result = self.advanced_scanner.perform_nmap_scan(target, scan_type)
        
        if not result.success:
            return f"❌ Scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Nmap Scan Results: {target}</b>\n\n"
        response += f"Scan Type: {scan_type}\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        response += f"Target Status: {result.result.get('status', 'unknown')}\n\n"
        
        if result.result and 'ports' in result.result:
            open_ports = [p for p in result.result['ports'] if p['state'] == 'open']
            response += f"🔒 <b>Open Ports: {len(open_ports)}</b>\n"
            
            for port in open_ports[:15]:
                port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
                if 'version' in port:
                    port_str += f" ({port['version']})"
                response += f"{port_str}\n"
            
            if len(open_ports) > 15:
                response += f"... and {len(open_ports) - 15} more\n"
        
        if result.vulnerabilities:
            response += "\n⚠️ <b>Potential Vulnerabilities:</b>\n"
            for vuln in result.vulnerabilities[:5]:
                response += f"Port {vuln['port']}: {vuln['issues'][0]}\n"
        
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        # Save to database
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, scan_type,
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        # Save to file
        save_path = self.advanced_scanner.save_scan_to_file(result, f"scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        
        return response
    
    async def handle_network_discovery(self, args: List[str]) -> str:
        """Handle /nmap_discovery command"""
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_discovery [network_range]</code>\nExample: /nmap_discovery 192.168.1.0/24"
        
        network_range = args[0]
        await self.send_telegram_message(f"🔍 Discovering hosts on {network_range}...")
        
        result = self.advanced_scanner.network_discovery(network_range)
        
        if not result['success']:
            return f"❌ Discovery failed: {result['error']}"
        
        response = f"🔍 <b>Network Discovery: {network_range}</b>\n\n"
        response += f"Hosts Found: {result['count']}\n"
        response += f"Scan Time: {result['execution_time']:.2f}s\n\n"
        
        if result['hosts']:
            response += "<b>Discovered Hosts:</b>\n"
            for i, host in enumerate(result['hosts'][:20], 1):
                response += f"{i}. {host}\n"
            
            if len(result['hosts']) > 20:
                response += f"... and {len(result['hosts']) - 20} more"
        else:
            response += "No hosts found"
        
        return response
    
    async def handle_stealth_scan(self, args: List[str]) -> str:
        """Handle /nmap_stealth command"""
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_stealth [IP]</code>"
        
        target = args[0]
        await self.send_telegram_message(f"🔍 Starting stealth scan on {target}...")
        
        result = self.advanced_scanner.stealth_scan(target)
        
        if not result['success']:
            return f"❌ Stealth scan failed: {result['error']}"
        
        response = f"🔍 <b>Stealth Scan Results: {target}</b>\n\n"
        response += f"Scan Type: SYN Stealth\n"
        response += f"Execution Time: {result['execution_time']:.2f}s\n\n"
        response += f"<code>{result['output'][:1000]}...</code>"
        
        return response
    
    async def handle_os_detection(self, args: List[str]) -> str:
        """Handle /nmap_os command"""
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_os [IP]</code>"
        
        target = args[0]
        await self.send_telegram_message(f"🔍 Detecting OS on {target}...")
        
        result = self.advanced_scanner.os_detection(target)
        
        if not result['success']:
            return f"❌ OS detection failed: {result['error']}"
        
        response = f"🔍 <b>OS Detection: {target}</b>\n\n"
        response += f"Execution Time: {result['execution_time']:.2f}s\n\n"
        response += f"<code>{result['output'][:1500]}</code>"
        
        return response
    
    async def handle_service_detection(self, args: List[str]) -> str:
        """Handle /nmap_services command"""
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_services [IP]</code>"
        
        target = args[0]
        await self.send_telegram_message(f"🔍 Detecting services on {target}...")
        
        result = self.advanced_scanner.service_detection(target)
        
        if not result['success']:
            return f"❌ Service detection failed: {result['error']}"
        
        response = f"🔍 <b>Service Detection: {target}</b>\n\n"
        response += f"Execution Time: {result['execution_time']:.2f}s\n\n"
        response += f"<code>{result['output'][:1500]}</code>"
        
        return response
    
    async def handle_scan_history(self, args: List[str]) -> str:
        """Handle /scan_history command"""
        try:
            scans = self.monitor.db_manager.get_scan_results(15)
            
            if not scans:
                return "📊 No scan results found"
            
            response = "📄 <b>Scan History</b>\n\n"
            
            for i, scan in enumerate(scans, 1):
                response += f"{i}. <b>{scan['target']}</b>\n"
                response += f"   Type: {scan['scan_type']}\n"
                response += f"   Time: {scan['timestamp']}\n"
                response += f"   ID: <code>{scan['scan_id']}</code>\n\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_scan_details(self, args: List[str]) -> str:
        """Handle /scan_details command"""
        if len(args) < 1:
            return "❌ Usage: <code>/scan_details [scan_id]</code>\nUse /scan_history to get IDs"
        
        scan_id = args[0]
        
        try:
            scan = self.monitor.db_manager.get_scan_details(scan_id)
            
            if not scan:
                return f"❌ Scan not found: {scan_id}"
            
            response = f"🔍 <b>Scan Details: {scan['target']}</b>\n\n"
            response += f"Scan ID: <code>{scan['scan_id']}</code>\n"
            response += f"Type: {scan['scan_type']}\n"
            response += f"Time: {scan['timestamp']}\n\n"
            
            if scan['open_ports']:
                open_ports = json.loads(scan['open_ports'])
                if open_ports:
                    response += f"🔒 <b>Open Ports: {len(open_ports)}</b>\n"
                    for port in open_ports[:10]:
                        response += f"Port {port['port']}/{port['protocol']}: {port['service']}\n"
            
            if scan['vulnerabilities']:
                vulnerabilities = json.loads(scan['vulnerabilities'])
                if vulnerabilities:
                    response += f"\n⚠️ <b>Vulnerabilities: {len(vulnerabilities)}</b>\n"
                    for vuln in vulnerabilities[:5]:
                        response += f"Port {vuln['port']}: {vuln['issues'][0]}\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_vulnerability_scan(self, args: List[str]) -> str:
        """Handle /vulnerability_scan command"""
        if len(args) < 1:
            return "❌ Usage: <code>/vulnerability_scan [IP]</code>"
        
        target = args[0]
        await self.send_telegram_message(f"⚠️ Starting vulnerability scan on {target}...")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'vulnerability')
        
        if not result.success:
            return f"❌ Vulnerability scan failed: {result.raw_output}"
        
        response = f"⚠️ <b>Vulnerability Scan: {target}</b>\n\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"⚠️ <b>Found {len(vulnerabilities)} potential vulnerabilities:</b>\n\n"
            
            for i, vuln in enumerate(vulnerabilities[:10], 1):
                response += f"{i}. Port {vuln['port']}:\n"
                for issue in vuln['issues'][:3]:
                    response += f"   - {issue}\n"
                response += "\n"
            
            if len(vulnerabilities) > 10:
                response += f"... and {len(vulnerabilities) - 10} more vulnerabilities\n"
        else:
            response += "✅ No vulnerabilities detected"
        
        # Save results
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, 'vulnerability',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            vulnerabilities,
            result.raw_output
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result, f"vuln_scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_full_scan(self, args: List[str]) -> str:
        """Handle /full_scan command"""
        if len(args) < 1:
            return "❌ Usage: <code>/full_scan [IP]</code>\nWarning: This scans ALL 65535 ports and may take a while!"
        
        target = args[0]
        await self.send_telegram_message(f"⏳ Starting FULL port scan on {target}... This may take several minutes.")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'full')
        
        if not result.success:
            return f"❌ Full scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Full Port Scan: {target}</b>\n\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔒 <b>Total Open Ports: {len(open_ports)}</b>\n\n"
        
        for port in open_ports[:20]:
            port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
            if 'version' in port:
                port_str += f" ({port['version']})"
            response += f"{port_str}\n"
        
        if len(open_ports) > 20:
            response += f"... and {len(open_ports) - 20} more\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"\n⚠️ <b>Vulnerabilities: {len(vulnerabilities)}</b>\n"
            for vuln in vulnerabilities[:5]:
                response += f"Port {vuln['port']}: {vuln['issues'][0]}\n"
        
        # Save results
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, 'full',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            vulnerabilities,
            result.raw_output
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result, f"full_scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_quick_scan(self, args: List[str]) -> str:
        """Handle /quick_scan command"""
        if len(args) < 1:
            return "❌ Usage: <code>/quick_scan [IP]</code>"
        
        target = args[0]
        await self.send_telegram_message(f"🔍 Starting quick scan on {target}...")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'quick')
        
        if not result.success:
            return f"❌ Quick scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Quick Scan: {target}</b>\n\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔒 <b>Open Ports: {len(open_ports)}</b>\n"
        
        for port in open_ports[:10]:
            response += f"Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        # Save results
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, 'quick',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result, f"quick_scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_port_scan(self, args: List[str]) -> str:
        """Handle /port_scan command"""
        if len(args) < 2:
            return "❌ Usage: <code>/port_scan [IP] [ports]</code>\nExample: /port_scan 192.168.1.1 80,443,22-100"
        
        target = args[0]
        ports = args[1]
        
        await self.send_telegram_message(f"🔍 Scanning ports {ports} on {target}...")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'quick', {'ports': ports})
        
        if not result.success:
            return f"❌ Port scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Port Scan: {target}</b>\n\n"
        response += f"Ports: {ports}\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔒 <b>Open Ports: {len(open_ports)}</b>\n"
        
        for port in open_ports:
            port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
            if 'version' in port:
                port_str += f" ({port['version']})"
            response += f"{port_str}\n"
        
        # Save results
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, 'custom',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result, f"port_scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_network_map(self, args: List[str]) -> str:
        """Handle /network_map command"""
        if len(args) < 1:
            return "❌ Usage: <code>/network_map [network_range]</code>\nExample: /network_map 192.168.1.0/24"
        
        network_range = args[0]
        await self.send_telegram_message(f"🌐 Creating network map for {network_range}...")
        
        result = self.advanced_scanner.network_discovery(network_range)
        
        if not result['success']:
            return f"❌ Network mapping failed: {result['error']}"
        
        response = f"🌐 <b>Network Map: {network_range}</b>\n\n"
        response += f"Hosts Discovered: {result['count']}\n"
        response += f"Scan Time: {result['execution_time']:.2f}s\n\n"
        
        if result['hosts']:
            response += "<b>Network Topology:</b>\n"
            for i, host in enumerate(result['hosts'][:30], 1):
                response += f"└── {host}\n"
            
            if len(result['hosts']) > 30:
                response += f"└── ... and {len(result['hosts']) - 30} more hosts\n"
        else:
            response += "No hosts found in network range"
        
        # Save network map to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_map_{network_range.replace('/', '_')}_{timestamp}.txt"
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        map_content = f"Network Map for {network_range}\n"
        map_content += f"Generated: {datetime.datetime.now().isoformat()}\n"
        map_content += f"Hosts Found: {result['count']}\n\n"
        
        if result['hosts']:
            map_content += "Discovered Hosts:\n"
            map_content += "================\n"
            for host in result['hosts']:
                map_content += f"{host}\n"
        
        with open(filepath, 'w') as f:
            f.write(map_content)
        
        response += f"\n💾 Network map saved to: {filepath}"
        
        return response
    
    async def handle_ping_ip(self, args: List[str]) -> str:
        """Handle /ping_ip command"""
        if len(args) < 1:
            return "❌ Usage: <code>/ping_ip [IP]</code>"
        
        ip = args[0]
        result = self.monitor.scanner.ping_ip(ip)
        
        preview = result[-1000:] if len(result) > 1000 else result
        return f"🏓 <b>Ping {ip}</b>\n\n<code>{preview}</code>"
    
    async def handle_tracert_ip(self, args: List[str]) -> str:
        """Handle /tracert_ip command"""
        if len(args) < 1:
            return "❌ Usage: <code>/tracert_ip [IP/domain]</code>"
        
        target = args[0]
        result = await self.monitor.scanner.traceroute(target)
        return result
    
    async def handle_whois(self, args: List[str]) -> str:
        """Handle /whois command"""
        if len(args) < 1:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        domain = args[0]
        
        try:
            result = self.monitor.scanner.whois_lookup(domain)
            return f"🔍 <b>WHOIS: {domain}</b>\n\n<code>{result[:1000]}</code>"
        except Exception as e:
            return f"❌ WHOIS lookup failed: {str(e)}"
    
    async def handle_dns_lookup(self, args: List[str]) -> str:
        """Handle /dns_lookup command"""
        if len(args) < 1:
            return "❌ Usage: <code>/dns_lookup [domain]</code>"
        
        domain = args[0]
        
        try:
            result = self.monitor.scanner.dns_lookup(domain)
            return f"🌐 <b>DNS Lookup: {domain}</b>\n\n<code>{result[:1000]}</code>"
        except Exception as e:
            return f"❌ DNS lookup failed: {str(e)}"
    
    async def handle_analyze_ip(self, args: List[str]) -> str:
        """Handle /analyze_ip command"""
        if len(args) < 1:
            return "❌ Usage: <code>/analyze_ip [IP]</code>"
        
        ip = args[0]
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        
        # Get location
        try:
            location = self.monitor.scanner.get_ip_location(ip)
            loc_data = json.loads(location)
            
            response += f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}\n"
            response += f"🏢 ISP: {loc_data.get('isp', loc_data.get('org', 'N/A'))}\n\n"
        except:
            pass
        
        # Check threats
        try:
            threats = self.monitor.db_manager.get_recent_threats(5)
            ip_threats = [t for t in threats if t['ip_address'] == ip]
            
            if ip_threats:
                response += f"⚠️ <b>Threats Found: {len(ip_threats)}</b>\n"
                for threat in ip_threats:
                    response += f"• {threat['threat_type']}: {threat['severity']}\n"
            else:
                response += "✅ No recent threats detected"
                
        except Exception as e:
            response += f"⚠️ Could not check threats: {str(e)}"
        
        return response
    
    async def handle_status(self, args: List[str]) -> str:
        """Handle /status command"""
        if not PSUTIL_AVAILABLE:
            return "❌ psutil not available. Install with: pip install psutil"
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            response = "📊 <b>System Status</b>\n\n"
            response += "✅ Bot: Online\n"
            response += f"🔍 Nmap: {'Available' if self.advanced_scanner.nmap_available else 'Not Available'}\n"
            response += f"💻 CPU: {cpu_percent:.1f}%\n"
            response += f"🧠 Memory: {mem.percent:.1f}%\n"
            response += f"🌐 Network: {network.bytes_recv / 1024:.0f} RX/s, {network.bytes_sent / 1024:.0f} TX/s\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error getting status: {str(e)}"
    
    async def handle_system_info(self, args: List[str]) -> str:
        """Handle /system_info command"""
        if not PSUTIL_AVAILABLE:
            return "❌ psutil not available. Install with: pip install psutil"
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            response = "💻 <b>System Information</b>\n\n"
            response += f"OS: {platform.system()} {platform.release()}\n"
            response += f"CPU: {platform.processor()}\n"
            response += f"CPU Usage: {cpu_percent:.1f}%\n"
            response += f"Memory: {mem.percent:.1f}%\n"
            response += f"Uptime: {int(time.time() - psutil.boot_time()) // 3600}h {(int(time.time() - psutil.boot_time()) % 3600) // 60}m\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_threat_summary(self, args: List[str]) -> str:
        """Handle /threat_summary command"""
        try:
            threats = self.monitor.db_manager.get_recent_threats(10)
            
            if not threats:
                return "✅ No recent threats detected"
            
            response = "⚠️ <b>Recent Threats</b>\n\n"
            
            for threat in threats:
                response += f"• <code>{threat['ip_address']}</code>\n"
                response += f"  Type: {threat['threat_type']} | Severity: {threat['severity']}\n"
                response += f"  Time: {threat['timestamp']}\n\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_generate_report(self, args: List[str]) -> str:
        """Handle /generate_report command"""
        try:
            threats = self.monitor.db_manager.get_recent_threats(50)
            scan_results = self.monitor.db_manager.get_scan_results(50)
            history = self.monitor.db_manager.get_command_history(100)
            
            report = {
                'generated_at': datetime.datetime.now().isoformat(),
                'system': {
                    'nmap_available': self.advanced_scanner.nmap_available,
                    'telegram_configured': bool(self.monitor.telegram_token and self.monitor.telegram_chat_id)
                },
                'statistics': {
                    'monitored_ips': len(self.monitor.monitored_ips),
                    'total_threats': len(threats),
                    'total_scans': len(scan_results),
                    'high_severity': len([t for t in threats if t['severity'] == 'high']),
                    'medium_severity': len([t for t in threats if t['severity'] == 'medium']),
                    'low_severity': len([t for t in threats if t['severity'] == 'low']),
                    'commands_executed': len(history)
                },
                'recent_scans': [{
                    'target': scan['target'],
                    'type': scan['scan_type'],
                    'timestamp': scan['timestamp']
                } for scan in scan_results[:10]],
                'recent_threats': [{
                    'ip': threat['ip_address'],
                    'type': threat['threat_type'],
                    'severity': threat['severity'],
                    'timestamp': threat['timestamp']
                } for threat in threats[:10]]
            }
            
            filename = f"security_report_{int(time.time())}.json"
            filepath = Path(REPORT_DIR) / filename
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            response = "📊 <b>Security Report Generated</b>\n\n"
            response += f"Monitored IPs: {report['statistics']['monitored_ips']}\n"
            response += f"Total Threats: {report['statistics']['total_threats']}\n"
            response += f"Total Scans: {report['statistics']['total_scans']}\n"
            response += f"High Severity: {report['statistics']['high_severity']}\n"
            response += f"Medium Severity: {report['statistics']['medium_severity']}\n"
            response += f"Low Severity: {report['statistics']['low_severity']}\n"
            response += f"\n✅ Report saved: <code>{filename}</code>"
            
            return response
            
        except Exception as e:
            return f"❌ Error generating report: {str(e)}"
    
    async def handle_custom_scan(self, args: List[str]) -> str:
        """Handle /custom_scan command"""
        if len(args) < 2:
            return "❌ Usage: <code>/custom_scan [IP] [nmap_options]</code>\nExample: /custom_scan 192.168.1.1 -sS -p 22,80,443 -O"
        
        target = args[0]
        custom_options = ' '.join(args[1:])
        
        await self.send_telegram_message(f"🔍 Starting custom scan with options: {custom_options}")
        
        result = self.advanced_scanner.perform_nmap_scan(target, custom_options)
        
        if not result.success:
            return f"❌ Custom scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Custom Scan: {target}</b>\n\n"
        response += f"Options: {custom_options}\n"
        response += f"Execution Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔒 <b>Open Ports: {len(open_ports)}</b>\n"
        
        for port in open_ports[:15]:
            response += f"Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        # Save results
        self.monitor.db_manager.save_scan_result(
            result.scan_id, target, 'custom',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result, f"custom_scan_{result.scan_id}.json")
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_compare_scans(self, args: List[str]) -> str:
        """Handle /compare_scans command"""
        if len(args) < 2:
            return "❌ Usage: <code>/compare_scans [scan_id1] [scan_id2]</code>"
        
        scan_id1, scan_id2 = args[0], args[1]
        
        try:
            scan1 = self.monitor.db_manager.get_scan_details(scan_id1)
            scan2 = self.monitor.db_manager.get_scan_details(scan_id2)
            
            if not scan1 or not scan2:
                return "❌ One or both scans not found"
            
            response = "🔍 <b>Comparing Scans</b>\n\n"
            response += f"<b>Scan 1:</b> {scan1['target']} ({scan1['scan_type']})\n"
            response += f"<b>Scan 2:</b> {scan2['target']} ({scan2['scan_type']})\n\n"
            
            ports1 = json.loads(scan1['open_ports']) if scan1['open_ports'] else []
            ports2 = json.loads(scan2['open_ports']) if scan2['open_ports'] else []
            
            open_ports1 = [p for p in ports1 if p['state'] == 'open']
            open_ports2 = [p for p in ports2 if p['state'] == 'open']
            
            response += "🔒 <b>Open Ports Comparison:</b>\n"
            response += f"Scan 1: {len(open_ports1)} open ports\n"
            response += f"Scan 2: {len(open_ports2)} open ports\n\n"
            
            if scan1['target'] == scan2['target']:
                common_ports = [p1 for p1 in open_ports1 if any(p2['port'] == p1['port'] for p2 in open_ports2)]
                unique_to_scan1 = [p1 for p1 in open_ports1 if not any(p2['port'] == p1['port'] for p2 in open_ports2)]
                unique_to_scan2 = [p2 for p2 in open_ports2 if not any(p1['port'] == p2['port'] for p1 in open_ports1)]
                
                response += f"Common ports: {len(common_ports)}\n"
                response += f"Unique to Scan 1: {len(unique_to_scan1)}\n"
                response += f"Unique to Scan 2: {len(unique_to_scan2)}\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def handle_nmap_advanced(self, args: List[str]) -> str:
        """Handle /nmap_advanced command"""
        return """🔍 <b>Advanced Nmap Options</b>

Use these scan types:
<code>/nmap_scan [IP] quick</code> - Fast scan
<code>/nmap_scan [IP] stealth</code> - Stealth SYN scan
<code>/nmap_scan [IP] comprehensive</code> - Full analysis
<code>/nmap_scan [IP] udp</code> - UDP ports
<code>/nmap_scan [IP] vulnerability</code> - Vuln scan
<code>/nmap_scan [IP] full</code> - All 65535 ports

Or use specialized commands:
<code>/nmap_stealth [IP]</code>
<code>/nmap_os [IP]</code>
<code>/nmap_services [IP]</code>
<code>/vulnerability_scan [IP]</code>"""
    
    async def handle_save_scan(self, args: List[str]) -> str:
        """Handle /save_scan command"""
        if len(args) < 1:
            return "❌ Usage: <code>/save_scan [scan_id]</code>"
        
        scan_id = args[0]
        
        try:
            scan = self.monitor.db_manager.get_scan_details(scan_id)
            
            if not scan:
                return f"❌ Scan not found: {scan_id}"
            
            scan_result = ScanResult(
                scan_id=scan['scan_id'],
                success=True,
                target=scan['target'],
                scan_type=scan['scan_type'],
                cmd='',
                execution_time=0,
                result={
                    'ports': json.loads(scan['open_ports']) if scan['open_ports'] else [],
                    'services': json.loads(scan['services']) if scan['services'] else [],
                    'os': scan['os_info'],
                    'vulnerabilities': json.loads(scan['vulnerabilities']) if scan['vulnerabilities'] else []
                },
                vulnerabilities=json.loads(scan['vulnerabilities']) if scan['vulnerabilities'] else [],
                raw_output=scan['raw_output'] or '',
                timestamp=scan['timestamp']
            )
            
            filepath = self.advanced_scanner.save_scan_to_file(scan_result, f"scan_{scan['scan_id']}.json")
            
            response = "💾 <b>Scan Saved</b>\n\n"
            response += f"Scan ID: <code>{scan['scan_id']}</code>\n"
            response += f"Target: {scan['target']}\n"
            response += f"Type: {scan['scan_type']}\n"
            response += f"Saved to: {filepath}"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def process_telegram_commands(self):
        """Process incoming Telegram commands"""
        if not self.monitor.telegram_token or not REQUESTS_AVAILABLE:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 10
            }
            
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200 and response.json().get('ok'):
                for update in response.json().get('result', []):
                    self.last_update_id = update['update_id']
                    
                    if 'message' in update and 'text' in update['message']:
                        await self.process_message(update['message'])
                        
        except Exception as e:
            print(f"Telegram error: {str(e)}")
    
    async def process_message(self, message: Dict):
        """Process individual Telegram message"""
        text = message['text']
        chat_id = str(message['chat']['id'])
        
        # Store chat ID if not already stored
        if not self.monitor.telegram_chat_id:
            self.monitor.telegram_chat_id = chat_id
            self.monitor.save_config()
        
        # Log command
        try:
            self.monitor.db_manager.log_command(text, 'telegram', True)
        except Exception as e:
            print(f"Error logging command: {str(e)}")
        
        # Parse command
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Handle command
        if command in self.command_handlers:
            try:
                if asyncio.iscoroutinefunction(self.command_handlers[command]):
                    response = await self.command_handlers[command](args)
                else:
                    response = self.command_handlers[command](args)
                
                await self.send_telegram_message(response)
            except Exception as e:
                await self.send_telegram_message(f"❌ Error: {str(e)}")
        else:
            await self.send_telegram_message("❌ Unknown command. Type /help")


class CybersecurityMonitor:
    """Main cybersecurity monitoring system"""
    
    def __init__(self):
        self.monitored_ips: Set[str] = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.advanced_scanner = AdvancedNetworkScanner()
        self.traceroute_tool = TracerouteTool()
        
        self.setup_logging()
        self.load_config()
    
    def setup_logging(self):
        """Initialize logging"""
        print("Logging initialized")
    
    def load_config(self):
        """Load configuration from file"""
        config_path = Path(CONFIG_FILE)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                self.telegram_token = config.get('telegram_token')
                self.telegram_chat_id = config.get('telegram_chat_id')
                self.monitored_ips = set(config.get('monitored_ips', []))
                
            except Exception as e:
                print(f"Config load error: {str(e)}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
                
        except Exception as e:
            print(f"Config save error: {str(e)}")
    
    async def load_monitored_ips_from_db(self):
        """Load monitored IPs from database"""
        try:
            ips = self.db_manager.get_monitored_ips()
            self.monitored_ips = set(ips)
        except Exception as e:
            print(f"Error loading IPs from DB: {str(e)}")


def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║       🛡️ ACCURATE ONLINE OS🛡️                                       ║
    ║                                                                      ║
    ║               Advanced Cybersecurity Platform                        ║
    ║                                                                      ║
    ║          🔍 Professional Network Scanner                            ║
    ║          🌐 Network Discovery & Mapping                             ║
    ║          ⚠️ Vulnerability Assessment                                ║
    ║          💾 Comprehensive Reporting                                 ║
    ║                                                                     ║
    ║   Community: https://github.com/Accurate-Cyber-Defense              ║
    ║                                                                     ║
    ║           Nmap Status: {}                                           ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════╝
    """
    
    nmap_status = "✅ READY" if AdvancedNetworkScanner().nmap_available else "⚠️ NOT INSTALLED"
    print(banner.format(nmap_status))


def check_nmap_installation():
    """Check Nmap installation status"""
    print("\n🔍 Checking for Nmap installation...")
    scanner = AdvancedNetworkScanner()
    return scanner.nmap_available


async def setup_telegram():
    """Setup Telegram bot configuration"""
    print("\n🔧 Telegram Bot Setup")
    print("=" * 50)
    print("\nTo use Telegram commands:")
    print("1. Create a bot with @BotFather on Telegram")
    print("2. Get your bot token")
    print("3. Start chat with your bot and send /start")
    print("4. Get your chat ID\n")
    
    token = input("Enter Telegram bot token (or press Enter to skip): ").strip()
    if not token:
        return None, None
    
    chat_id = input("Enter your chat ID: ").strip()
    
    return token, chat_id


def show_nmap_install_instructions():
    """Show Nmap installation instructions"""
    print("\n🔍 <b>NMAP INSTALLATION INSTRUCTIONS</b>")
    print("=" * 50)
    print("\nTo use advanced scanning features, install Nmap:")
    print("\n📦 <b>Windows:</b>")
    print("   1. Download from: https://nmap.org/download.html")
    print("   2. Run installer")
    print("   3. Add Nmap to PATH during installation")
    print("\n🍎 <b>macOS:</b>")
    print("   brew install nmap")
    print("\n🐧 <b>Linux:</b>")
    print("   sudo apt-get install nmap  # Ubuntu/Debian")
    print("   sudo yum install nmap      # CentOS/RHEL")
    print("\n✅ After installation, restart this application.")
    print("\n")


async def telegram_processor(telegram_handler):
    """Telegram command processor loop"""
    while True:
        try:
            await telegram_handler.process_telegram_commands()
            await asyncio.sleep(2)
        except Exception as e:
            print(f"Telegram error: {str(e)}")
            await asyncio.sleep(10)


async def handle_local_commands(monitor, telegram_handler):
    """Handle local terminal commands"""
    print("\n💻 Local terminal commands available")
    print("📋 Type 'help' for command list\n")
    print(f"📁 Scan results directory: {SCAN_RESULTS_DIR}")
    print(f"📁 Reports directory: {REPORT_DIR}")
    print("\n")
    
    while True:
        try:
            command = input("accurateOS> ").strip()
            
            if not command:
                continue
            
            if command.lower() == 'exit':
                print("👋 Exiting...")
                break
            
            await process_local_command(monitor, telegram_handler, command)
            
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")


async def process_local_command(monitor, telegram_handler, command: str):
    """Process a local command"""
    # Log command
    try:
        monitor.db_manager.log_command(command, 'local', True)
    except Exception as e:
        print(f"Error logging command: {str(e)}")
    
    # Parse command
    parts = command.split()
    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []
    
    # Command handlers
    if cmd == 'help':
        print_help()
    
    elif cmd == 'ping' and args:
        result = monitor.scanner.ping_ip(args[0])
        print(result)
    
    elif cmd in ['tracert', 'traceroute'] and args:
        print(f"Traceroute to {args[0]}...")
        result = await monitor.scanner.traceroute(args[0])
        print(result)
    
    elif cmd == 'whois' and args:
        try:
            result = monitor.scanner.whois_lookup(args[0])
            print(result)
        except Exception as e:
            print(f"❌ WHOIS lookup failed: {str(e)}")
    
    elif cmd == 'dns' and args:
        try:
            result = monitor.scanner.dns_lookup(args[0])
            print(result)
        except Exception as e:
            print(f"❌ DNS lookup failed: {str(e)}")
    
    elif cmd == 'location' and args:
        result = monitor.scanner.get_ip_location(args[0])
        print(result)
    
    elif cmd == 'analyze' and args:
        ip = args[0]
        print(f"\n🔍 Analyzing {ip}...\n")
        
        # Get location
        try:
            location = monitor.scanner.get_ip_location(ip)
            loc_data = json.loads(location)
            print(f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}")
            print(f"🏢 ISP: {loc_data.get('isp', loc_data.get('org', 'N/A'))}\n")
        except:
            pass
        
        # Check threats
        try:
            threats = monitor.db_manager.get_recent_threats(10)
            ip_threats = [t for t in threats if t['ip_address'] == ip]
            
            if ip_threats:
                print(f"⚠️ Threats Found: {len(ip_threats)}")
                for threat in ip_threats:
                    print(f"  • {threat['threat_type']}: {threat['severity']}")
            else:
                print("✅ No recent threats detected")
                
        except Exception as e:
            print(f"⚠️ Could not check threats: {str(e)}")
    
    elif cmd == 'add' and args:
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            monitor.monitored_ips.add(ip)
            monitor.db_manager.add_monitored_ip(ip)
            monitor.save_config()
            print(f"✅ Added {ip}")
        except ValueError:
            print(f"❌ Invalid IP: {ip}")
    
    elif cmd == 'remove' and args:
        ip = args[0]
        if ip in monitor.monitored_ips:
            monitor.monitored_ips.remove(ip)
            monitor.db_manager.remove_monitored_ip(ip)
            monitor.save_config()
            print(f"✅ Removed {ip}")
        else:
            print(f"❌ IP not in list: {ip}")
    
    elif cmd == 'list':
        if monitor.monitored_ips:
            print("\n📋 Monitored IPs:")
            for ip in sorted(monitor.monitored_ips):
                print(f"  • {ip}")
        else:
            print("📋 No IPs are being monitored")
    
    elif cmd == 'stop':
        if monitor.monitored_ips:
            ips = list(monitor.monitored_ips)
            monitor.monitored_ips.clear()
            for ip in ips:
                monitor.db_manager.remove_monitored_ip(ip)
            monitor.save_config()
            print(f"🛑 Stopped monitoring: {', '.join(ips)}")
        else:
            print("⚠️ No IPs are being monitored")
    
    elif cmd == 'network_info':
        print("\n🌐 Network Information:")
        print(f"  Hostname: {socket.gethostname()}")
        
        try:
            interfaces = psutil.net_if_addrs()
            print(f"  Interfaces: {len(interfaces)}")
            
            for iface, addrs in list(interfaces.items())[:3]:
                print(f"  {iface}:")
                for addr in addrs[:2]:
                    print(f"    {addr.address} ({addr.family.name})")
                    
        except:
            pass
    
    elif cmd == 'system_info':
        if PSUTIL_AVAILABLE:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                
                print("\n💻 System Information:")
                print(f"  OS: {platform.system()} {platform.release()}")
                print(f"  CPU: {platform.processor()}")
                print(f"  CPU Usage: {cpu_percent:.1f}%")
                print(f"  Memory: {mem.percent:.1f}%")
                print(f"  Uptime: {int(time.time() - psutil.boot_time()) // 3600}h {(int(time.time() - psutil.boot_time()) % 3600) // 60}m")
                
            except Exception as e:
                print(f"❌ Error: {str(e)}")
        else:
            print("❌ psutil not available")
    
    elif cmd == 'status':
        if PSUTIL_AVAILABLE:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                
                print("\n📊 System Status:")
                print(f"  Bot: {'Online' if monitor.telegram_token else 'Offline'}")
                print(f"  Nmap: {'Available' if monitor.advanced_scanner.nmap_available else 'Not Available'}")
                print(f"  Monitored IPs: {len(monitor.monitored_ips)}")
                print(f"  CPU: {cpu_percent:.1f}%")
                print(f"  Memory: {mem.percent:.1f}%")
                print(f"  Uptime: {int(time.time() - psutil.boot_time()) // 3600}h {(int(time.time() - psutil.boot_time()) % 3600) // 60}m")
                
            except Exception as e:
                print(f"❌ Error: {str(e)}")
        else:
            print("❌ psutil not available")
    
    elif cmd == 'history':
        try:
            history = monitor.db_manager.get_command_history(20)
            
            if history:
                print("\n📜 Command History:")
                for i, row in enumerate(history, 1):
                    status = "✅" if row['success'] else "❌"
                    print(f"  {i}. {status} [{row['source']}] {row['command']} | {row['timestamp']}")
            else:
                print("📜 No commands recorded")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'threats':
        try:
            threats = monitor.db_manager.get_recent_threats(10)
            
            if threats:
                print("\n⚠️ Recent Threats:")
                for threat in threats:
                    print(f"  • {threat['ip_address']}")
                    print(f"    Type: {threat['threat_type']} | Severity: {threat['severity']}")
                    print(f"    Time: {threat['timestamp']}\n")
            else:
                print("✅ No recent threats detected")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'report':
        try:
            threats = monitor.db_manager.get_recent_threats(50)
            history = monitor.db_manager.get_command_history(100)
            
            report = {
                'generated_at': datetime.datetime.now().isoformat(),
                'monitored_ips': len(monitor.monitored_ips),
                'total_threats': len(threats),
                'high_severity': len([t for t in threats if t['severity'] == 'high']),
                'medium_severity': len([t for t in threats if t['severity'] == 'medium']),
                'low_severity': len([t for t in threats if t['severity'] == 'low']),
                'commands_executed': len(history)
            }
            
            filename = f"report_{int(time.time())}.json"
            filepath = Path(REPORT_DIR) / filename
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            print("\n📊 Security Report:")
            print(f"  Monitored IPs: {report['monitored_ips']}")
            print(f"  Total Threats: {report['total_threats']}")
            print(f"  High Severity: {report['high_severity']}")
            print(f"  Medium Severity: {report['medium_severity']}")
            print(f"  Low Severity: {report['low_severity']}")
            print(f"\n✅ Report saved: {filename}")
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'scan_history':
        try:
            scans = monitor.db_manager.get_scan_results(15)
            
            if not scans:
                print("📊 No scan results found")
            else:
                print("\n📊 Scan History:")
                for i, scan in enumerate(scans, 1):
                    print(f"  {i}. {scan['target']}")
                    print(f"     Type: {scan['scan_type']}")
                    print(f"     Time: {scan['timestamp']}")
                    print(f"     ID: {scan['scan_id']}\n")
                    
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'scan_details' and args:
        scan_id = args[0]
        
        try:
            scan = monitor.db_manager.get_scan_details(scan_id)
            
            if not scan:
                print(f"❌ Scan not found: {scan_id}")
                return
            
            print("\n📊 Scan Details:")
            print(f"  Target: {scan['target']}")
            print(f"  Type: {scan['scan_type']}")
            print(f"  Time: {scan['timestamp']}")
            print(f"  ID: {scan['scan_id']}")
            
            if scan['open_ports']:
                ports = json.loads(scan['open_ports'])
                open_ports = [p for p in ports if p['state'] == 'open']
                
                if open_ports:
                    print(f"\n  Open Ports: {len(open_ports)}")
                    for port in open_ports[:10]:
                        print(f"    Port {port['port']}/{port['protocol']}: {port['service']}")
                        
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'save_scan' and args:
        scan_id = args[0]
        
        try:
            scan = monitor.db_manager.get_scan_details(scan_id)
            
            if not scan:
                print(f"❌ Scan not found: {scan_id}")
                return
            
            scan_result = ScanResult(
                scan_id=scan['scan_id'],
                success=True,
                target=scan['target'],
                scan_type=scan['scan_type'],
                cmd='',
                execution_time=0,
                result={
                    'ports': json.loads(scan['open_ports']) if scan['open_ports'] else [],
                    'services': json.loads(scan['services']) if scan['services'] else [],
                    'os': scan['os_info'],
                    'vulnerabilities': json.loads(scan['vulnerabilities']) if scan['vulnerabilities'] else []
                },
                vulnerabilities=json.loads(scan['vulnerabilities']) if scan['vulnerabilities'] else [],
                raw_output=scan['raw_output'] or '',
                timestamp=scan['timestamp']
            )
            
            filepath = monitor.advanced_scanner.save_scan_to_file(scan_result, f"scan_{scan['scan_id']}.json")
            
            print("\n💾 Scan Saved\n")
            print(f"  Scan ID: {scan['scan_id']}")
            print(f"  Target: {scan['target']}")
            print(f"  Type: {scan['scan_type']}")
            print(f"  Saved to: {filepath}")
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'compare_scans' and len(args) >= 2:
        scan_id1, scan_id2 = args[0], args[1]
        
        try:
            scan1 = monitor.db_manager.get_scan_details(scan_id1)
            scan2 = monitor.db_manager.get_scan_details(scan_id2)
            
            if not scan1 or not scan2:
                print("❌ One or both scans not found")
                return
            
            print("\n🔍 Comparing Scans")
            print(f"\n  Scan 1: {scan1['target']} ({scan1['scan_type']})")
            print(f"  Scan 2: {scan2['target']} ({scan2['scan_type']})")
            
            ports1 = json.loads(scan1['open_ports']) if scan1['open_ports'] else []
            ports2 = json.loads(scan2['open_ports']) if scan2['open_ports'] else []
            
            open_ports1 = [p for p in ports1 if p['state'] == 'open']
            open_ports2 = [p for p in ports2 if p['state'] == 'open']
            
            print("\n  Open Ports Comparison:")
            print(f"    Scan 1: {len(open_ports1)} open ports")
            print(f"    Scan 2: {len(open_ports2)} open ports")
            
            if scan1['target'] == scan2['target']:
                common_ports = [p1 for p1 in open_ports1 if any(p2['port'] == p1['port'] for p2 in open_ports2)]
                unique_to_scan1 = [p1 for p1 in open_ports1 if not any(p2['port'] == p1['port'] for p2 in open_ports2)]
                unique_to_scan2 = [p2 for p2 in open_ports2 if not any(p1['port'] == p2['port'] for p1 in open_ports1)]
                
                print(f"\n    Common ports: {len(common_ports)}")
                print(f"    Unique to Scan 1: {len(unique_to_scan1)}")
                print(f"    Unique to Scan 2: {len(unique_to_scan2)}")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif cmd == 'nmap_scan' and len(args) >= 2:
        target, scan_type = args[0], args[1]
        print(f"🔍 Starting {scan_type} scan on {target}...")
        
        result = monitor.advanced_scanner.perform_nmap_scan(target, scan_type)
        
        if not result.success:
            print(f"❌ Scan failed: {result.raw_output}")
            return
        
        response = f"\n✅ Scan Completed\n\n"
        response += f"  Target: {target}\n"
        response += f"  Type: {scan_type}\n"
        response += f"  Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"  Open Ports: {len(open_ports)}\n"
        
        for port in open_ports[:10]:
            response += f"    Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"\n  ⚠️  Vulnerabilities: {len(vulnerabilities)}\n"
            for vuln in vulnerabilities[:3]:
                response += f"    Port {vuln['port']}: {vuln['issues'][0]}\n"
        
        response += f"\n  Scan ID: {result.scan_id}"
        print(response)
        
        # Save to database
        monitor.db_manager.save_scan_result(
            result.scan_id, target, scan_type,
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        # Save to file
        filepath = monitor.advanced_scanner.save_scan_to_file(result, f"scan_{result.scan_id}.json")
        print(f"  💾 Saved to: {filepath}")
    
    elif cmd == 'nmap_discovery' and args:
        network_range = args[0]
        print(f"🔍 Discovering hosts on {network_range}...")
        
        result = monitor.advanced_scanner.network_discovery(network_range)
        
        if not result['success']:
            print(f"❌ Discovery failed: {result['error']}")
            return
        
        response = f"\n🌐 Network Discovery: {network_range}\n\n"
        response += f"  Hosts Found: {result['count']}\n"
        response += f"  Scan Time: {result['execution_time']:.2f}s\n"
        
        if result['hosts']:
            response += "\n  Discovered Hosts:\n"
            for i, host in enumerate(result['hosts'][:20], 1):
                response += f"    {i}. {host}\n"
            
            if len(result['hosts']) > 20:
                response += f"    ... and {len(result['hosts']) - 20} more\n"
        else:
            response += "  No hosts found\n"
        
        print(response)
        
        # Save network map
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_map_{network_range.replace('/', '_')}_{timestamp}.txt"
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        map_content = f"Network Map for {network_range}\n"
        map_content += f"Generated: {datetime.datetime.now().isoformat()}\n"
        map_content += f"Hosts Found: {result['count']}\n\n"
        
        if result['hosts']:
            map_content += "Discovered Hosts:\n"
            map_content += "================\n"
            for host in result['hosts']:
                map_content += f"{host}\n"
        
        with open(filepath, 'w') as f:
            f.write(map_content)
        
        print(f"  💾 Network map saved to: {filepath}")
    
    elif cmd == 'nmap_stealth' and args:
        target = args[0]
        print(f"🔍 Starting stealth scan on {target}...")
        
        result = monitor.advanced_scanner.stealth_scan(target)
        
        if not result['success']:
            print(f"❌ Stealth scan failed: {result['error']}")
            return
        
        response = f"\n🕵️ Stealth Scan Results: {target}\n\n"
        response += f"  Time: {result['execution_time']:.2f}s\n"
        response += f"  Output:\n{result['output'][:1000]}"
        
        if len(result['output']) > 1000:
            response += "..."
        
        print(response)
    
    elif cmd == 'nmap_os' and args:
        target = args[0]
        print(f"🔍 Detecting OS on {target}...")
        
        result = monitor.advanced_scanner.os_detection(target)
        
        if not result['success']:
            print(f"❌ OS detection failed: {result['error']}")
            return
        
        response = f"\n💻 OS Detection: {target}\n\n"
        response += f"  Time: {result['execution_time']:.2f}s\n"
        response += f"  Output:\n{result['output'][:1500]}"
        
        print(response)
    
    elif cmd == 'nmap_services' and args:
        target = args[0]
        print(f"🔍 Detecting services on {target}...")
        
        result = monitor.advanced_scanner.service_detection(target)
        
        if not result['success']:
            print(f"❌ Service detection failed: {result['error']}")
            return
        
        response = f"\n🔧 Service Detection: {target}\n\n"
        response += f"  Time: {result['execution_time']:.2f}s\n"
        response += f"  Output:\n{result['output'][:1500]}"
        
        print(response)
    
    elif cmd == 'vulnerability_scan' and args:
        target = args[0]
        print(f"⚠️ Starting vulnerability scan on {target}...")
        
        result = monitor.advanced_scanner.perform_nmap_scan(target, 'vulnerability')
        
        if not result.success:
            print(f"❌ Vulnerability scan failed: {result.raw_output}")
            return
        
        response = f"\n⚠️ Vulnerability Scan: {target}\n\n"
        response += f"  Time: {result.execution_time:.2f}s\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"  Found {len(vulnerabilities)} potential vulnerabilities:\n"
            for i, vuln in enumerate(vulnerabilities[:10], 1):
                response += f"    {i}. Port {vuln['port']}:\n"
                for issue in vuln['issues'][:3]:
                    response += f"      - {issue}\n"
        else:
            response += "  ✅ No vulnerabilities detected"
        
        response += f"\n  Scan ID: {result.scan_id}"
        print(response)
        
        # Save results
        monitor.db_manager.save_scan_result(
            result.scan_id, target, 'vulnerability',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            vulnerabilities,
            result.raw_output
        )
        
        filepath = monitor.advanced_scanner.save_scan_to_file(result, f"vuln_scan_{result.scan_id}.json")
        print(f"  💾 Saved to: {filepath}")
    
    elif cmd == 'full_scan' and args:
        target = args[0]
        print(f"⏳ Starting FULL port scan on {target}... This may take several minutes.")
        
        result = monitor.advanced_scanner.perform_nmap_scan(target, 'full')
        
        if not result.success:
            print(f"❌ Full scan failed: {result.raw_output}")
            return
        
        response = f"\n🔍 Full Port Scan: {target}\n\n"
        response += f"  Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"  Total Open Ports: {len(open_ports)}\n"
        
        for port in open_ports[:20]:
            response += f"    Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        if len(open_ports) > 20:
            response += f"    ... and {len(open_ports) - 20} more\n"
        
        response += f"\n  Scan ID: {result.scan_id}"
        print(response)
        
        # Save results
        monitor.db_manager.save_scan_result(
            result.scan_id, target, 'full',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        filepath = monitor.advanced_scanner.save_scan_to_file(result, f"full_scan_{result.scan_id}.json")
        print(f"  💾 Saved to: {filepath}")
    
    elif cmd == 'quick_scan' and args:
        target = args[0]
        print(f"🔍 Starting quick scan on {target}...")
        
        result = monitor.advanced_scanner.perform_nmap_scan(target, 'quick')
        
        if not result.success:
            print(f"❌ Quick scan failed: {result.raw_output}")
            return
        
        response = f"\n⚡ Quick Scan: {target}\n\n"
        response += f"  Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"  Open Ports: {len(open_ports)}\n"
        
        for port in open_ports[:10]:
            response += f"    Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        response += f"\n  Scan ID: {result.scan_id}"
        print(response)
        
        # Save results
        monitor.db_manager.save_scan_result(
            result.scan_id, target, 'quick',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        filepath = monitor.advanced_scanner.save_scan_to_file(result, f"quick_scan_{result.scan_id}.json")
        print(f"  💾 Saved to: {filepath}")
    
    elif cmd == 'port_scan' and len(args) >= 2:
        target, ports = args[0], args[1]
        print(f"🔍 Scanning ports {ports} on {target}...")
        
        result = monitor.advanced_scanner.perform_nmap_scan(target, 'quick', {'ports': ports})
        
        if not result.success:
            print(f"❌ Port scan failed: {result.raw_output}")
            return
        
        response = f"\n🔍 Port Scan: {target}\n\n"
        response += f"Ports: {ports}\n"
        response += f"Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"Open Ports: {len(open_ports)}\n"
        
        for port in open_ports:
            port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
            if 'version' in port:
                port_str += f" ({port['version']})"
            response += f"  {port_str}\n"
        
        response += f"\nScan ID: {result.scan_id}"
        print(response)
        
        # Save results
        monitor.db_manager.save_scan_result(
            result.scan_id, target, 'custom',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output
        )
        
        filepath = monitor.advanced_scanner.save_scan_to_file(result, f"port_scan_{result.scan_id}.json")
        print(f"💾 Saved to: {filepath}")
    
    elif cmd == 'network_map' and args:
        network_range = args[0]
        print(f"🌐 Creating network map for {network_range}...")
        
        result = monitor.advanced_scanner.network_discovery(network_range)
        
        if not result['success']:
            print(f"❌ Network mapping failed: {result['error']}")
            return
        
        response = f"\n🗺️ Network Map: {network_range}\n\n"
        response += f"  Hosts Discovered: {result['count']}\n"
        response += f"  Scan Time: {result['execution_time']:.2f}s\n"
        
        if result['hosts']:
            response += "\n  Network Topology:\n"
            for i, host in enumerate(result['hosts'][:30], 1):
                response += f"  └── {host}\n"
            
            if len(result['hosts']) > 30:
                response += f"  └── ... and {len(result['hosts']) - 30} more hosts\n"
        else:
            response += "  No hosts found in network range\n"
        
        print(response)
        
        # Save network map
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_map_{network_range.replace('/', '_')}_{timestamp}.txt"
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        map_content = f"Network Map for {network_range}\n"
        map_content += f"Generated: {datetime.datetime.now().isoformat()}\n"
        map_content += f"Hosts Found: {result['count']}\n\n"
        
        if result['hosts']:
            map_content += "Discovered Hosts:\n"
            map_content += "================\n"
            for host in result['hosts']:
                map_content += f"{host}\n"
        
        with open(filepath, 'w') as f:
            f.write(map_content)
        
        print(f"  💾 Network map saved to: {filepath}")
    
    elif cmd == 'config':
        token, chat_id = await setup_telegram()
        if token and chat_id:
            monitor.telegram_token = token
            monitor.telegram_chat_id = chat_id
            monitor.save_config()
            print("✅ Telegram configured!")
    
    elif cmd == 'clear':
        os.system('cls' if platform.system() == 'Windows' else 'clear')
        print_banner()
    
    else:
        print("❌ Unknown command. Type 'help' for available commands.")


def print_help():
    """Print help information"""
    print("""
🛠️  <b>ADVANCED NMAP COMMANDS</b> 🛠️
  nmap_scan [ip] [type]     - Nmap scan (quick,stealth,comprehensive,udp,vulnerability,full)
  nmap_discovery [range]    - Network discovery (192.168.1.0/24)
  nmap_stealth [ip]         - Stealth SYN scan
  nmap_os [ip]              - OS detection
  nmap_services [ip]        - Service version detection
  vulnerability_scan [ip]   - Vulnerability scan
  full_scan [ip]            - Full port scan (65535 ports)
  quick_scan [ip]           - Quick scan (common ports)
  port_scan [ip] [ports]    - Custom port scan (80,443,22-100)
  network_map [range]       - Create network map
  scan_history              - View scan history
  scan_details [id]         - View scan details
  save_scan [id]            - Save scan to file
  compare_scans [id1] [id2] - Compare two scans

🌐 <b>NETWORK TOOLS</b> 🌐
  ping [ip]                 - Ping IP address
  tracert [ip]              - Traceroute
  traceroute [ip]           - Traceroute
  whois [domain]            - WHOIS lookup
  dns [domain]              - DNS lookup
  analyze [ip]              - Analyze IP
  location [ip]             - Get IP location

📊 <b>SYSTEM & MONITORING</b> 📊
  network_info              - Network information
  system_info               - System information
  status                    - System status
  history                   - Command history
  threats                   - Threat summary
  report                    - Generate security report

⚙️  <b>CONFIGURATION</b> ⚙️
  config                    - Configure Telegram
  clear                     - Clear screen
  exit                      - Exit program
    """)


async def main():
    """Main application entry point"""
    # Initialize monitor
    monitor = CybersecurityMonitor()
    telegram_handler = TelegramBotHandler(monitor)
    
    # Print banner
    print_banner()
    
    # Check Nmap
    check_nmap_installation()
    
    # Load monitored IPs
    await monitor.load_monitored_ips_from_db()
    
    # Setup Telegram if not configured
    if not monitor.telegram_token:
        token, chat_id = await setup_telegram()
        if token and chat_id:
            monitor.telegram_token = token
            monitor.telegram_chat_id = chat_id
            monitor.save_config()
            print("✅ Telegram configured!")
        else:
            print("⚠️ Telegram features disabled")
    
    # Start Telegram processor if configured
    if monitor.telegram_token and monitor.telegram_chat_id:
        print("✅ Telegram bot ACTIVE")
        print("📱 Send /start to your bot on Telegram")
        
        # Start Telegram processor in background
        telegram_task = asyncio.create_task(telegram_processor(telegram_handler))
        
        # Send startup message
        test_msg = """🚀 <b>Accurate Online OS v3.0 - Advanced Edition</b>

✅ Bot is online and ready!
🔍 Nmap: {} READY
🌐 Type /help for advanced commands
⚠️ Professional cybersecurity tools available""".format(
            'READY' if monitor.advanced_scanner.nmap_available else 'NOT INSTALLED'
        )
        
        await telegram_handler.send_telegram_message(test_msg)
    
    # Start local command handler
    await handle_local_commands(monitor, telegram_handler)


if __name__ == "__main__":
    import asyncio
    
    # Handle application errors
    import traceback
    
    def handle_exception(exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions"""
        print(f"❌ Uncaught Exception: {exc_value}")
        traceback.print_exception(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = handle_exception
    
    # Show Nmap instructions if not available
    if not AdvancedNetworkScanner().nmap_available:
        show_nmap_install_instructions()
    
    # Run the application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Thank you for using Accurate Online OS Advanced Edition!")
    except Exception as e:
        print(f"❌ Application error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)