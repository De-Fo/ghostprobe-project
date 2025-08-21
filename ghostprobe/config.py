
"""
Configuration settings for GhostProbe
"""

import os
from pathlib import Path

class Config:
    # Base paths
    BASE_DIR = Path(__file__).parent
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / "reports"
    
    # Wordlist files
    SUBDOMAIN_WORDLIST = DATA_DIR / "subdomain_wordlist.txt"
    BACKUP_WORDLIST = DATA_DIR / "backup_wordlist.txt" 
    IOT_CREDS_FILE = DATA_DIR / "iot_creds.json"
    
    # Scan settings
    DEFAULT_THREADS = 10
    DEFAULT_TIMEOUT = 10
    MAX_REDIRECTS = 5
    
    # Rate limiting
    REQUEST_DELAY = 0.1  # Minimum delay between requests
    MAX_REQUESTS_PER_SECOND = 10
    
    # Proxy settings
    DEFAULT_PROXY_PORT = 8080
    
    # Report settings
    HTML_TEMPLATE_PATH = BASE_DIR / "templates" / "report.html"
    
    # Web preview settings (optional)
    WEB_PREVIEW_HOST = "127.0.0.1"
    WEB_PREVIEW_PORT = 8000
    RATE_LIMIT_PER_IP = 10  # requests per hour
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they don't exist"""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        
        # Create templates directory for future HTML templates
        (cls.BASE_DIR / "templates").mkdir(exist_ok=True)

# Initialize directories on import
Config.ensure_directories()
