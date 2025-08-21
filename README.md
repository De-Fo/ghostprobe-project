
# GhostProbe

**Modular, offline-first pentesting toolkit** focused on real-world security gaps that are often overlooked in traditional scans.

## Features

### Core Modules
- **Subdomain Triage** - Discovers subdomains and identifies takeover risks
- **Forgotten Uploads Scanner** - Finds backup files and forgotten uploads
- **Session Hijack Detector** - Tests for session management vulnerabilities
- **IoT Default Cred Sweeper** - Scans for IoT devices with default credentials

### Multiple Interfaces
- **CLI** - Command-line interface for automation
- **Desktop GUI** - Cross-platform desktop application
- **Web Preview** - Limited demo mode for one module

## Quick Start

### Installation

bash
# Clone the repository
git clone [https://github.com/De-Fo/ghostprobe-project.git](https://github.com/De-Fo/ghostprobe-project.git)
cd ghostprobe

# [Optional but Recommended] Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies in editable mode
pip install -e .


### Basic Usage

# Scan a domain with multiple modules
python -m ghostprobe.cli scan example.com --modules subdomain,uploads

# IoT scanning with subnet range
python -m ghostprobe.cli scan 192.168.1.0/24 --modules iot --subnet-range 192.168.1.1-254

# Generate both JSON and HTML reports
python -m ghostprobe.cli scan target.com --modules subdomain,uploads --format both --output my_scan

# List available modules
python -m ghostprobe.cli modules


### Advanced Options# High-intensity scan with custom settings
python -m ghostprobe.cli scan example.com \
  --modules subdomain,uploads,iot \
  --wordlist-size large \
  --upload-threads 20 \
  --subnet-range 192.168.1.1-100 \
  --verbose

# Session hijack detection (requires proxy setup)
python -m ghostprobe.cli scan target.com --modules session --proxy-port 8080


## Module Details

### Subdomain Triage
- Brute-force subdomain enumeration
- CNAME takeover detection
- TLS certificate analysis
- Risk-based prioritization

### Forgotten Uploads Scanner
- Tests for common backup file patterns
- Parallel scanning with rate limiting
- Content-based risk assessment
- Finds `.bak`, `.old`, `.sql`, `.zip` files and more

### IoT Default Credentials
- Network device discovery
- Banner-based device identification
- Automated credential testing
- Vendor-specific default passwords

### Session Hijack Detector
- Proxy-based traffic analysis
- Session token validation
- Cross-account access testing
- Manual setup required


## Project Structure

ghostprobe-project/  
├── ghostprobe/       
│   ├── core/                  # Core scanning modules
│   │   ├── subdomain.py      # Subdomain enumeration
│   │   ├── uploads.py        # Backup file scanner
│   │   ├── session.py        # Session hijack detector
│   │   ├── iot.py           # IoT device scanner
│   │   └── utils.py         # Report generation
|   |
│   ├── gui/                  # Desktop GUI (future)
|   |   ├── main.py
|   |   └── components/
|   |   
│   ├── web_preview/          # Web demo (future)
|   |   ├── app.py
|   |   └── limiter.py
|   |
│   ├── data/                 # Wordlists and signatures
│   │   ├── subdomain_wordlist.txt
│   │   ├── backup_wordlist.txt
│   │   └── iot_creds.json
|   |
│   ├── __init__.py            
│   ├── cli.py               # Main CLI interface
│   └── config.py            # Configuration settings
|
├── setup.py
├── requirements.txt
├── README.md
└── LICENSE.txt

## Roadmap

### Phase 1 - CLI MVP
- [x] Basic CLI framework
- [x] Subdomain enumeration
- [x] Upload scanner
- [x] JSON/HTML reporting

### Phase 2 - Enhanced Modules
- [ ] IoT scanner improvements
- [ ] Session hijack detection
- [ ] Advanced wordlists
- [ ] Performance optimizations

### Phase 3 - GUI Application
- [ ] Cross-platform desktop app (Tauri/PySide6)
- [ ] Interactive dashboard
- [ ] Real-time scan monitoring

### Phase 4 - Web Preview
- [ ] FastAPI demo server
- [ ] Rate-limited public access
- [ ] Subdomain triage only

## Security Notice

This tool is intended for authorized penetration testing and security research only. Users are responsible for complying with all applicable laws and obtaining proper authorization before scanning any targets.

## License

MIT License - see LICENSE file for details.

## Honesty
Hey, lastly this, it's a tool built in one sitting for now, so don't expect magic.
Sometimes works, sometimes doesn't.
Only tried out on windows for now where only the python -m  option of running it was working.
Also the make build was breaking it so I removed that.
After more testing and actually running it on UNIX, will do more updates and additions to it.
Thanks for reading.

**GhostProbe** - Automating tests you need to run.
