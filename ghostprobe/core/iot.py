
"""
IoT Default Credentials Scanner
Scans for IoT devices with default credentials
"""

import asyncio
import socket
import httpx
from typing import List, Dict, Any
import json
import base64
from ipaddress import IPv4Network

class IoTScanner:
    def __init__(self):
        # Common IoT device signatures and default credentials
        self.device_signatures = {
            'Boa': {'vendor': 'GoAhead', 'default_creds': [('admin', 'admin'), ('root', 'root')]},
            'GoAhead': {'vendor': 'GoAhead', 'default_creds': [('admin', ''), ('admin', 'admin')]},
            'Allegro RomPager': {'vendor': 'Allegro', 'default_creds': [('admin', 'password')]},
            'lighttpd': {'vendor': 'Various', 'default_creds': [('admin', 'admin'), ('user', 'user')]},
            'mini_httpd': {'vendor': 'ACME', 'default_creds': [('admin', '1234')]}
        }
        
        self.common_ports = [80, 443, 8080, 8081, 8443, 9000, 10000]
    
    async def scan(self, target: str, subnet_range: str = None) -> List[Dict[str, Any]]:
        """Scan for IoT devices with default credentials"""
        findings = []
        
        # Generate IP range to scan
        if subnet_range:
            ip_range = self._parse_subnet_range(subnet_range)
        else:
            # Single target
            ip_range = [target]
        
        # Scan each IP
        for ip in ip_range[:10]:  # Limit to first 10 IPs for demo
            device_findings = await self._scan_ip(ip)
            findings.extend(device_findings)
        
        return findings
    
    def _parse_subnet_range(self, subnet_range: str) -> List[str]:
        """Parse subnet range into list of IPs"""
        # Simple range parser (e.g., "192.168.1.1-254")
        if '-' in subnet_range:
            base, end = subnet_range.rsplit('-', 1)
            base_parts = base.split('.')
            if len(base_parts) == 4:
                network_base = '.'.join(base_parts[:3])
                start_host = int(base_parts[3])
                end_host = int(end)
                
                return [f"{network_base}.{i}" for i in range(start_host, min(end_host + 1, 256))]
        
        return [subnet_range]
    
    async def _scan_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Scan a single IP for IoT devices"""
        findings = []
        
        for port in self.common_ports:
            device_info = await self._check_device(ip, port)
            if device_info:
                findings.append(device_info)
        
        return findings
    
    async def _check_device(self, ip: str, port: int) -> Dict[str, Any]:
        """Check if a device is an IoT device with default creds"""
        try:
            url = f"http://{ip}:{port}"
            
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                
                # Check server header for IoT signatures
                server_header = response.headers.get('server', '').lower()
                
                for signature, device_info in self.device_signatures.items():
                    if signature.lower() in server_header:
                        # Try default credentials
                        cred_result = await self._test_default_creds(
                            url, device_info['default_creds']
                        )
                        
                        if cred_result['success']:
                            return {
                                "type": "iot",
                                "value": f"{ip}:{port}",
                                "risk": "critical",
                                "details": f"IoT device with default credentials: {cred_result['creds']}"
                            }
                        else:
                            return {
                                "type": "iot", 
                                "value": f"{ip}:{port}",
                                "risk": "medium",
                                "details": f"IoT device detected: {device_info['vendor']}"
                            }
        
        except Exception:
            pass
        
        return None
    
    async def _test_default_creds(self, url: str, creds_list: List[tuple]) -> Dict[str, Any]:
        """Test default credentials against a device"""
        for username, password in creds_list:
            try:
                auth = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {'Authorization': f'Basic {auth}'}
                
                async with httpx.AsyncClient(timeout=5) as client:
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code == 200 and 'login' not in response.text.lower():
                        return {
                            'success': True,
                            'creds': f"{username}:{password}"
                        }
            
            except Exception:
                continue
        
        return {'success': False, 'creds': None}

