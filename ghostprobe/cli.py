
"""
Ghostprobe - Modular Offline-First Pentesting Toolkit
CLI Interface and Core Engine
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import concurrent.futures
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

# Core modules
from .core.subdomain import SubdomainTriage
from .core.uploads import UploadScanner
from .core.session import SessionHijackDetector
from .core.iot import IoTScanner
from .core.utils import ReportGenerator, RiskLevel

console = Console()

class GhostProbe:
    """Main GhostProbe toolkit orchestrator"""
    
    def __init__(self):
        self.modules = {
            'subdomain': SubdomainTriage(),
            'uploads': UploadScanner(),
            'session': SessionHijackDetector(),
            'iot': IoTScanner()
        }
        self.findings = []
        
    async def scan(self, target: str, modules: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute scan with specified modules"""
        if options is None:
            options = {}
            
        console.print(f"🔍 [bold cyan]Starting GhostProbe scan on {target}[/bold cyan]")
        
        scan_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "modules_run": modules,
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Run modules concurrently where possible
            tasks = []
            for module_name in modules:
                if module_name in self.modules:
                    task = progress.add_task(f"Running {module_name}...", total=None)
                    tasks.append((module_name, task))
            
            # Execute modules
            for module_name, task_id in tasks:
                try:
                    progress.update(task_id, description=f"[green]Running {module_name}...")
                    module = self.modules[module_name]
                    
                    if module_name == 'subdomain':
                        results = await module.scan(target, options.get('wordlist_size', 'medium'))
                    elif module_name == 'uploads':
                        results = await module.scan(target, options.get('upload_threads', 10))
                    elif module_name == 'session':
                        results = await module.scan(target, options.get('proxy_port', 8080))
                    elif module_name == 'iot':
                        results = await module.scan(target, options.get('subnet_range'))
                    
                    scan_results["findings"].extend(results)
                    progress.update(task_id, description=f"[green]✓ {module_name} completed")
                    
                except Exception as e:
                    progress.update(task_id, description=f"[red]✗ {module_name} failed: {str(e)}")
                    console.print(f"[red]Module {module_name} failed: {str(e)}[/red]")
        
        # Calculate summary stats
        for finding in scan_results["findings"]:
            risk = finding.get("risk", "info")
            scan_results["summary"]["total_findings"] += 1
            scan_results["summary"][risk] += 1
        
        return scan_results

def create_parser():
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="GhostProbe - Modular Offline-First Pentesting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghostprobe scan example.com --modules subdomain,uploads
  ghostprobe scan 192.168.1.0/24 --modules iot --subnet-range 192.168.1.1-254
  ghostprobe scan target.com --modules session --proxy-port 8080
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run penetration test scan')
    scan_parser.add_argument('target', help='Target domain, IP, or subnet')
    scan_parser.add_argument('--modules', '-m', 
                           default='subdomain,uploads',
                           help='Comma-separated modules to run (default: subdomain,uploads)')
    scan_parser.add_argument('--output', '-o', 
                           default='reports/scan_report',
                           help='Output file prefix (default: reports/scan_report)')
    scan_parser.add_argument('--format', '-f',
                           choices=['json', 'html', 'both'],
                           default='both',
                           help='Output format (default: both)')
    scan_parser.add_argument('--wordlist-size', 
                           choices=['small', 'medium', 'large'],
                           default='medium',
                           help='Wordlist size for subdomain enumeration')
    scan_parser.add_argument('--upload-threads', 
                           type=int, default=10,
                           help='Thread count for upload scanning (default: 10)')
    scan_parser.add_argument('--proxy-port', 
                           type=int, default=8080,
                           help='Proxy port for session hijack detection (default: 8080)')
    scan_parser.add_argument('--subnet-range',
                           help='IP range for IoT scanning (e.g., 192.168.1.1-254)')
    scan_parser.add_argument('--verbose', '-v', 
                           action='store_true',
                           help='Enable verbose output')
    
    # List modules command
    list_parser = subparsers.add_parser('modules', help='List available modules')
    
    return parser

def display_results(results: Dict[str, Any]):
    """Display scan results in a formatted table"""
    console.print("\n" + "="*60)
    console.print("[bold green]📊 SCAN RESULTS[/bold green]")
    console.print("="*60)
    
    # Summary table
    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")
    
    summary = results["summary"]
    summary_table.add_row("Target", results["target"])
    summary_table.add_row("Total Findings", str(summary["total_findings"]))
    summary_table.add_row("Critical", f"[red]{summary['critical']}[/red]")
    summary_table.add_row("High", f"[orange1]{summary['high']}[/orange1]")
    summary_table.add_row("Medium", f"[yellow]{summary['medium']}[/yellow]")
    summary_table.add_row("Low", f"[green]{summary['low']}[/green]")
    summary_table.add_row("Info", f"[blue]{summary['info']}[/blue]")
    
    console.print(summary_table)
    
    if results["findings"]:
        console.print("\n[bold yellow]🔍 Detailed Findings[/bold yellow]")
        
        # Group findings by type
        findings_by_type = {}
        for finding in results["findings"]:
            finding_type = finding["type"]
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
        
        for finding_type, findings in findings_by_type.items():
            console.print(f"\n[bold cyan]{finding_type.upper()} FINDINGS[/bold cyan]")
            
            findings_table = Table()
            findings_table.add_column("Value", style="white")
            findings_table.add_column("Risk", style="bold")
            findings_table.add_column("Details", style="dim")
            
            for finding in findings:
                risk_color = {
                    "critical": "red",
                    "high": "orange1", 
                    "medium": "yellow",
                    "low": "green",
                    "info": "blue"
                }.get(finding["risk"], "white")
                
                findings_table.add_row(
                    finding["value"],
                    f"[{risk_color}]{finding['risk'].upper()}[/{risk_color}]",
                    finding.get("details", "")
                )
            
            console.print(findings_table)

def list_modules():
    """Display available modules"""
    console.print("[bold cyan]📦 Available Modules[/bold cyan]\n")
    
    modules_info = {
        "subdomain": "Subdomain enumeration with takeover detection",
        "uploads": "Forgotten files and backup scanner", 
        "session": "Session hijacking vulnerability detector",
        "iot": "IoT device scanner with default credentials"
    }
    
    table = Table()
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="white")
    
    for module, description in modules_info.items():
        table.add_row(module, description)
    
    console.print(table)

async def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'modules':
        list_modules()
        return
    
    if args.command == 'scan':
        # Create output directory
        output_path = Path(args.output).parent
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Parse modules
        modules = [m.strip() for m in args.modules.split(',')]
        
        # Validate modules
        valid_modules = ['subdomain', 'uploads', 'session', 'iot']
        invalid_modules = [m for m in modules if m not in valid_modules]
        if invalid_modules:
            console.print(f"[red]Invalid modules: {', '.join(invalid_modules)}[/red]")
            console.print(f"Valid modules: {', '.join(valid_modules)}")
            sys.exit(1)
        
        # Prepare scan options
        options = {
            'wordlist_size': args.wordlist_size,
            'upload_threads': args.upload_threads,
            'proxy_port': args.proxy_port,
            'subnet_range': args.subnet_range,
            'verbose': args.verbose
        }
        
        # Run scan
        ghost_probe = GhostProbe()
        try:
            results = await ghost_probe.scan(args.target, modules, options)
            
            # Display results
            display_results(results)
            
            # Generate reports
            report_gen = ReportGenerator()
            
            if args.format in ['json', 'both']:
                json_file = f"{args.output}.json"
                with open(json_file, 'w') as f:
                    json.dump(results, f, indent=2)
                console.print(f"\n[green]📄 JSON report saved: {json_file}[/green]")
            
            if args.format in ['html', 'both']:
                html_file = f"{args.output}.html"
                report_gen.generate_html_report(results, html_file)
                console.print(f"[green]📄 HTML report saved: {html_file}[/green]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"\n[red]❌ Scan failed: {str(e)}[/red]")
            sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
        sys.exit(0)