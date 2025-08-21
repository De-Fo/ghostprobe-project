
"""
Subdomain Triage Module
Enumerates subdomains and identifies potential takeover risks
"""

import asyncio
import dns.resolver
import httpx
import ssl
import socket
from typing import List, Dict, Any
from urllib.parse import urlparse
import re

class SubdomainTriage:
    def __init__(self):
        self.wordlists = {
            'small': ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'staging'],
            'medium': ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'staging', 'api', 'app', 
                      'cms', 'blog', 'shop', 'store', 'vpn', 'remote', 'secure', 'portal',
                      'dashboard', 'console', 'panel', 'cpanel', 'webmail', 'mx', 'ns1', 'ns2'],
            'large': []  # Would load from external wordlist file
        }
        
        self.takeover_signatures = {
            'github.io': ['There isn\'t a GitHub Pages site here'],
            'herokuapp.com': ['No such app'],
            'cloudfront.net': ['Bad Request'],
            'amazonaws.com': ['NoSuchBucket'],
            'azurewebsites.net': ['404 - Web app not found']
        }
    
    async def scan(self, target: str, wordlist_size: str = 'medium') -> List[Dict[str, Any]]:
        """Main subdomain scanning method"""
        findings = []
        
        # Generate subdomain list
        subdomains = await self._generate_subdomains(target, wordlist_size)
        
        # Resolve subdomains
        resolved_subs = await self._resolve_subdomains(subdomains)
        
        # Check each resolved subdomain
        for subdomain in resolved_subs:
            finding = await self._analyze_subdomain(subdomain)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def _generate_subdomains(self, domain: str, wordlist_size: str) -> List[str]:
        """Generate list of subdomains to test"""
        wordlist = self.wordlists.get(wordlist_size, self.wordlists['medium'])
        return [f"{word}.{domain}" for word in wordlist]
    
    async def _resolve_subdomains(self, subdomains: List[str]) -> List[str]:
        """Resolve subdomains to filter out non-existent ones"""
        resolved = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        
        for subdomain in subdomains:
            try:
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    resolved.append(subdomain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception:
                pass
        
        return resolved
    
    async def _analyze_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Analyze a subdomain for potential issues"""
        finding = None
        
        # Check for CNAME takeover
        takeover_risk = await self._check_cname_takeover(subdomain)
        if takeover_risk:
            finding = {
                "type": "subdomain",
                "value": subdomain,
                "risk": "high",
                "details": f"Potential subdomain takeover via {takeover_risk}"
            }
        
        # Check for interesting keywords
        if not finding and self._has_interesting_keywords(subdomain):
            finding = {
                "type": "subdomain", 
                "value": subdomain,
                "risk": "medium",
                "details": "Potentially interesting subdomain (dev/test/staging)"
            }
        
        # Check TLS issues
        if not finding:
            tls_issue = await self._check_tls_issues(subdomain)
            if tls_issue:
                finding = {
                    "type": "subdomain",
                    "value": subdomain,
                    "risk": "medium", 
                    "details": f"TLS issue: {tls_issue}"
                }
        
        # Default info finding for valid subdomains
        if not finding:
            finding = {
                "type": "subdomain",
                "value": subdomain,
                "risk": "info",
                "details": "Active subdomain discovered"
            }
        
        return finding
    
    async def _check_cname_takeover(self, subdomain: str) -> str:
        """Check if subdomain has potential CNAME takeover"""
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(subdomain, 'CNAME')
            
            for rdata in answers:
                cname = str(rdata.target).lower()
                
                # Check against known vulnerable services
                for service, signatures in self.takeover_signatures.items():
                    if service in cname:
                        # Test if service returns vulnerable response
                        async with httpx.AsyncClient(timeout=5) as client:
                            try:
                                response = await client.get(f"http://{subdomain}")
                                for signature in signatures:
                                    if signature in response.text:
                                        return service
                            except:
                                pass
        except:
            pass
        
        return None
    
    def _has_interesting_keywords(self, subdomain: str) -> bool:
        """Check if subdomain contains interesting keywords"""
        keywords = ['dev', 'test', 'staging', 'admin', 'panel', 'console', 'internal']
        return any(keyword in subdomain.lower() for keyword in keywords)
    
    async def _check_tls_issues(self, subdomain: str) -> str:
        """Check for TLS certificate issues"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((subdomain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check if cert is expired (simplified check)
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        return "Expired certificate"
        except ssl.SSLError as e:
            return f"SSL Error: {str(e)}"
        except:
            pass
        
        return None
