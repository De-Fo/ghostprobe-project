
"""
Forgotten Uploads Scanner
Searches for common backup files and forgotten uploads
"""

import asyncio
import httpx
from typing import List, Dict, Any
from pathlib import Path
import time
import random

class UploadScanner:
    def __init__(self):
        self.backup_extensions = [
            '.bak', '.old', '.backup', '.zip', '.tar.gz', '.rar', '.7z',
            '.sql', '.db', '.sqlite', '.swp', '.tmp', '.log', '.conf',
            '.config', '.ini', '.xml', '.json', '.csv', '.txt'
        ]
        
        self.common_paths = [
            'backup', 'backups', 'old', 'temp', 'tmp', 'archive', 'uploads',
            'files', 'data', 'db', 'database', 'sql', 'config', 'conf'
        ]
        
        self.sensitive_files = [
            'database.sql', 'backup.sql', 'users.sql', 'config.php',
            'wp-config.php', 'settings.php', '.env', 'credentials.txt',
            'passwords.txt', 'users.csv', 'database.db'
        ]
    
    async def scan(self, target: str, max_threads: int = 10) -> List[Dict[str, Any]]:
        """Scan for forgotten uploads and backup files"""
        findings = []
        
        # Generate URL list to test
        urls_to_test = self._generate_test_urls(target)
        
        # Test URLs with controlled concurrency
        semaphore = asyncio.Semaphore(max_threads)
        tasks = [self._test_url(url, semaphore) for url in urls_to_test]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result:
                findings.append(result)
        
        return findings
    
    def _generate_test_urls(self, target: str) -> List[str]:
        """Generate list of URLs to test for forgotten files"""
        if not target.startswith('http'):
            target = f"http://{target}"
        
        urls = []
        base_url = target.rstrip('/')
        
        # Test direct sensitive files
        for file in self.sensitive_files:
            urls.append(f"{base_url}/{file}")
        
        # Test common paths + extensions
        for path in self.common_paths:
            for ext in self.backup_extensions:
                urls.append(f"{base_url}/{path}{ext}")
                urls.append(f"{base_url}/{path}/{path}{ext}")
        
        # Test index files with backup extensions
        for ext in self.backup_extensions:
            urls.append(f"{base_url}/index.php{ext}")
            urls.append(f"{base_url}/index.html{ext}")
        
        return urls
    
    async def _test_url(self, url: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """Test a single URL for accessibility"""
        async with semaphore:
            # Random delay to avoid overwhelming target
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                    response = await client.head(url)
                    
                    if response.status_code == 200:
                        # Get content length for additional context
                        content_length = response.headers.get('content-length', '0')
                        
                        risk_level = self._assess_risk(url, response)
                        
                        return {
                            "type": "upload",
                            "value": url,
                            "risk": risk_level,
                            "details": f"Accessible file (size: {content_length} bytes)"
                        }
            
            except Exception:
                pass
        
        return None
    
    def _assess_risk(self, url: str, response) -> str:
        """Assess risk level based on file type and characteristics"""
        url_lower = url.lower()
        
        # Critical files
        if any(critical in url_lower for critical in ['.sql', '.db', 'password', 'credential', '.env']):
            return 'critical'
        
        # High risk files  
        if any(high in url_lower for high in ['config', 'backup', '.zip', '.tar']):
            return 'high'
        
        # Medium risk
        if any(medium in url_lower for medium in ['.bak', '.old', '.log']):
            return 'medium'
        
        return 'low'
