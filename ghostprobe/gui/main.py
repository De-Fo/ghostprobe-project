# gui/main.py
"""
GhostProbe Desktop GUI Application
Cross-platform interface using PySide6
"""

import sys
import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QLabel, QLineEdit, QPushButton, QCheckBox, QTextEdit, QTabWidget,
    QGroupBox, QSpinBox, QComboBox, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QTreeWidget, QTreeWidgetItem, QStatusBar
)
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QFont, QIcon, QPalette, QColor

# Corrected imports for the GhostProbe package
# This assumes the project structure:
# ghostprobe-project/
# ├── ghostprobe/
# │   ├── core/
# │   └── cli.py
# └── gui/
#     └── main.py
try:
    from ghostprobe.cli import GhostProbe
    from ghostprobe.core.utils import ReportGenerator
except ImportError:
    # Fallback for local testing, though proper packaging is the goal
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from ghostprobe.cli import GhostProbe
    from ghostprobe.core.utils import ReportGenerator


class ScanWorker(QThread):
    """Worker thread for running scans without blocking UI"""
    
    progress_updated = Signal(str)
    scan_completed = Signal(dict)
    scan_error = Signal(str)
    
    def __init__(self, target: str, modules: list, options: dict):
        super().__init__()
        self.target = target
        self.modules = modules
        self.options = options
        self.ghost_probe = GhostProbe()
    
    def run(self):
        """Run the scan in background thread"""
        try:
            self.progress_updated.emit("Initializing scan...")
            
            # Create event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run the scan
            # We need to pass the progress_updated signal to the CLI,
            # so we'll need to modify the CLI to accept and use it.
            # For now, we'll just run the scan as is.
            results = loop.run_until_complete(
                self.ghost_probe.scan(self.target, self.modules, self.options)
            )
            
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.scan_error.emit(str(e))
        finally:
            self.progress_updated.emit("Scan completed")


class ResultsWidget(QWidget):
    """Widget for displaying scan results"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Results tree
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(['Finding', 'Risk', 'Details'])
        layout.addWidget(self.results_tree)
        
        # Export buttons
        export_layout = QHBoxLayout()
        self.export_json_btn = QPushButton("Export JSON")
        self.export_html_btn = QPushButton("Export HTML")
        self.export_json_btn.clicked.connect(self.export_json)
        self.export_html_btn.clicked.connect(self.export_html)
        
        export_layout.addWidget(self.export_json_btn)
        export_layout.addWidget(self.export_html_btn)
        export_layout.addStretch()
        
        layout.addLayout(export_layout)
        self.setLayout(layout)
        
        self.current_results = None
    
    def update_results(self, results: Dict[str, Any]):
        """Update the results display"""
        self.current_results = results
        self.results_tree.clear()
        
        # Group findings by type
        findings_by_type = {}
        for finding in results.get("findings", []):
            finding_type = finding["type"]
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
        
        # Add findings to tree
        for finding_type, findings in findings_by_type.items():
            type_item = QTreeWidgetItem(self.results_tree)
            type_item.setText(0, f"{finding_type.upper()} ({len(findings)})")
            type_item.setExpanded(True)
            
            for finding in findings:
                finding_item = QTreeWidgetItem(type_item)
                finding_item.setText(0, finding["value"])
                finding_item.setText(1, finding["risk"].upper())
                finding_item.setText(2, finding.get("details", ""))
                
                # Color code by risk level
                risk_colors = {
                    "critical": QColor(220, 53, 69),
                    "high": QColor(253, 126, 20),
                    "medium": QColor(255, 193, 7),
                    "low": QColor(40, 167, 69),
                    "info": QColor(23, 162, 184)
                }
                
                color = risk_colors.get(finding["risk"], QColor(0, 0, 0))
                finding_item.setForeground(1, color)
    
    def export_json(self):
        """Export results as JSON"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "ghostprobe_report.json", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_results, f, indent=2)
                QMessageBox.information(self, "Success", f"Report saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {str(e)}")
    
    def export_html(self):
        """Export results as HTML"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "ghostprobe_report.html", "HTML Files (*.html)"
        )
        
        if file_path:
            try:
                report_gen = ReportGenerator()
                report_gen.generate_html_report(self.current_results, file_path)
                QMessageBox.information(self, "Success", f"Report saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {str(e)}")


class GhostProbeGUI(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.setup_ui()
        self.setup_style()
    
    def setup_ui(self):
        """Set up the user interface"""
        self.setWindowTitle("GhostProbe - Pentesting Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        central_widget.setLayout(QVBoxLayout())
        central_widget.layout().addWidget(main_splitter)
        
        # Left panel - Configuration
        config_widget = self.create_config_widget()
        main_splitter.addWidget(config_widget)
        
        # Right panel - Results
        self.results_widget = ResultsWidget()
        main_splitter.addWidget(self.results_widget)
        
        # Set splitter proportions
        main_splitter.setSizes([400, 800])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready to scan")
        
        # Progress bar (initially hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
    def setup_style(self):
        """Set up the dark theme and font styles"""
        self.setStyleSheet("""
            QWidget {
                background-color: #2e2e2e;
                color: #ffffff;
            }
            QMainWindow {
                background-color: #2e2e2e;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 5px;
                margin-top: 1ex;
                background-color: #3e3e3e;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: #fff;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #4e4e4e;
                border: 1px solid #5e5e5e;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #007acc;
                border: none;
                color: white;
                padding: 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #005f99;
            }
            QCheckBox {
                spacing: 5px;
            }
            QTreeWidget {
                background-color: #3e3e3e;
                border: 1px solid #444;
                alternate-background-color: #353535;
                show-decoration-selected: 1;
            }
            QTreeView::item:selected {
                background-color: #007acc;
            }
        """)

    def create_config_widget(self):
        """Create the configuration panel"""
        config_widget = QWidget()
        layout = QVBoxLayout()
        
        # Target input
        target_group = QGroupBox("Target")
        target_layout = QVBoxLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or 192.168.1.0/24")
        target_layout.addWidget(QLabel("Domain or IP Range:"))
        target_layout.addWidget(self.target_input)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Modules selection
        modules_group = QGroupBox("Modules")
        modules_layout = QVBoxLayout()
        
        self.module_checkboxes = {}
        modules = [
            ("subdomain", "Subdomain Triage", True),
            ("uploads", "Forgotten Uploads Scanner", True), 
            ("session", "Session Hijack Detector", False),
            ("iot", "IoT Default Cred Sweeper", False)
        ]
        
        for module_id, module_name, default_checked in modules:
            checkbox = QCheckBox(module_name)
            checkbox.setChecked(default_checked)
            self.module_checkboxes[module_id] = checkbox
            modules_layout.addWidget(checkbox)
        
        modules_group.setLayout(modules_layout)
        layout.addWidget(modules_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        # Wordlist size
        options_layout.addWidget(QLabel("Subdomain Wordlist Size:"))
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems(["Small", "Medium", "Large"])
        options_layout.addWidget(self.wordlist_combo)
        
        # Upload threads
        options_layout.addWidget(QLabel("Upload Threads:"))
        self.upload_threads_spin = QSpinBox()
        self.upload_threads_spin.setRange(1, 50)
        self.upload_threads_spin.setValue(10)
        options_layout.addWidget(self.upload_threads_spin)
        
        # Proxy port
        options_layout.addWidget(QLabel("Proxy Port:"))
        self.proxy_port_input = QLineEdit("8080")
        options_layout.addWidget(self.proxy_port_input)
        
        # Subnet range
        options_layout.addWidget(QLabel("Subnet Range (for IoT):"))
        self.subnet_range_input = QLineEdit()
        self.subnet_range_input.setPlaceholderText("e.g., 192.168.1.1-254")
        options_layout.addWidget(self.subnet_range_input)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Scan button
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_scan)
        layout.addWidget(scan_button)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        config_widget.setLayout(layout)
        return config_widget

    def start_scan(self):
        """Collects options and starts the scan in a separate thread"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Target cannot be empty.")
            return

        selected_modules = [
            module_id for module_id, checkbox in self.module_checkboxes.items()
            if checkbox.isChecked()
        ]
        if not selected_modules:
            QMessageBox.warning(self, "Input Error", "Please select at least one module.")
            return
            
        options = {
            'wordlist_size': self.wordlist_combo.currentText().lower(),
            'upload_threads': self.upload_threads_spin.value(),
            'proxy_port': int(self.proxy_port_input.text()),
            'subnet_range': self.subnet_range_input.text().strip(),
            'verbose': True # Assuming verbose output for GUI console
        }
        
        # Show progress bar and update status
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress bar
        self.status_bar.showMessage("Scan in progress...")
        
        # Start the worker thread
        self.scan_worker = ScanWorker(target, selected_modules, options)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_completed.connect(self.on_scan_completed)
        self.scan_worker.scan_error.connect(self.on_scan_error)
        self.scan_worker.start()

    def update_progress(self, message: str):
        """Updates the status bar with progress messages from the worker"""
        self.status_bar.showMessage(message)

    def on_scan_completed(self, results: Dict[str, Any]):
        """Handles a completed scan, updates UI with results"""
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("Scan completed successfully!")
        self.results_widget.update_results(results)

    def on_scan_error(self, message: str):
        """Handles a scan error"""
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("Scan failed!")
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan: {message}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GhostProbeGUI()
    window.show()
    sys.exit(app.exec())