import sys
import nmap
from fpdf import FPDF
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
                             QTextEdit, QTabWidget, QProgressBar, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette, QIcon


class ScannerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(list, list)

    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip

    def run(self):
        self.update_signal.emit(f"\n🔍 Scanning {self.target_ip}...\n")
        self.progress_signal.emit(10)
        open_ports, firewall_issues = self.scan_ports_and_firewall()
        self.progress_signal.emit(100)
        self.finished_signal.emit(open_ports, firewall_issues)

    def scan_ports_and_firewall(self):
        scanner = nmap.PortScanner()
        scanner.scan(self.target_ip, arguments="-p 1-1000 -sV -sC --script=firewall-bypass,firewalk,vuln")
        open_ports = []
        firewall_issues = []
        self.progress_signal.emit(40)

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port].get('version', 'N/A')
                    severity = self.get_severity(service, version)
                    open_ports.append({'port': port, 'service': service, 'version': version, 'severity': severity})
                    self.update_signal.emit(f"Port {port}: {service} (Version: {version}) - Severity: {severity}\n")

            if 'script' in scanner[host]:
                for script_name, script_output in scanner[host]['script'].items():
                    if "firewall" in script_name or "bypass" in script_name or "firewalk" in script_name:
                        firewall_issues.append(f"{script_name}: {script_output.strip()}")
                        self.update_signal.emit(f" Firewall Issue: {script_name} - {script_output.strip()}\n")

        self.progress_signal.emit(80)
        return open_ports, firewall_issues

    def get_severity(self, service, version):
        if service == "http" and "Apache" in version:
            return "High"
        elif service == "ftp" and "vsftpd" in version:
            return "Critical"
        elif service == "ssh" and "OpenSSH" in version:
            return "Medium"
        return "Low"


class FirewallScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Firewall Audit & Security Scanner")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon('icon.png'))  # Add your custom icon here

        # Set overall window style
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(50, 50, 50))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        self.setPalette(palette)

        layout = QVBoxLayout()

        self.label = QLabel("Enter Target IP:")
        self.label.setFont(QFont("Arial", 14))
        self.label.setStyleSheet("color: #FFFFFF;")
        layout.addWidget(self.label)

        self.ip_input = QLineEdit()
        self.ip_input.setFont(QFont("Arial", 12))
        self.ip_input.setStyleSheet("background-color: #333333; color: white; border: 1px solid #444444; padding: 5px;")
        layout.addWidget(self.ip_input)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #4CAF50;
                border-radius: 10px;
                background-color: #2C2F3B;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 10px;
            }
            QProgressBar::green {
                background-color: #4CAF50;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Tabs
        self.tabs = QTabWidget()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("background-color: #2c2c2c; color: white; border: none; padding: 10px;")
        self.tabs.addTab(self.result_text, "Scan Results")

        self.firewall_text = QTextEdit()
        self.firewall_text.setReadOnly(True)
        self.firewall_text.setStyleSheet("background-color: #2c2c2c; color: white; border: none; padding: 10px;")
        self.tabs.addTab(self.firewall_text, "Firewall Issues")

        layout.addWidget(self.tabs)

        # Spacer at the bottom for aesthetics
        spacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        layout.addItem(spacer)

        self.setLayout(layout)

    def start_scan(self):
        target_ip = self.ip_input.text().strip()
        if not target_ip:
            self.result_text.setText(" Please enter a valid IP address.")
            return

        self.result_text.setText(f" Starting scan for {target_ip}...\n")
        self.progress_bar.setValue(5)

        self.scanner_thread = ScannerThread(target_ip)
        self.scanner_thread.update_signal.connect(self.update_results)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def update_results(self, message):
        self.result_text.append(message)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def scan_finished(self, open_ports, firewall_issues):
        self.firewall_text.setText("\n".join(firewall_issues) if firewall_issues else "No firewall vulnerabilities detected.")
        self.generate_pdf(self.ip_input.text(), open_ports, firewall_issues)
        self.result_text.append("\n📄 PDF report generated: Firewall_Audit_Report.pdf")
        self.progress_bar.setValue(100)

    def generate_pdf(self, target, open_ports, firewall_issues):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=16)
        pdf.cell(200, 10, "Firewall & Security Scan Report", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, f"Target: {target}", ln=True)
        pdf.cell(200, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(50, 10, "Port", 1)
        pdf.cell(50, 10, "Service", 1)
        pdf.cell(50, 10, "Version", 1)
        pdf.cell(50, 10, "Severity", 1)
        pdf.ln()

        pdf.set_font("Arial", size=12)
        for port_info in open_ports:
            pdf.cell(50, 10, str(port_info['port']), 1)
            pdf.cell(50, 10, port_info['service'], 1)
            pdf.cell(50, 10, port_info['version'], 1)
            pdf.cell(50, 10, port_info['severity'], 1)
            pdf.ln()

        pdf.output("Firewall_Audit_Report.pdf")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FirewallScannerApp()
    window.show()
    sys.exit(app.exec())