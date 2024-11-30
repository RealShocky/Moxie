import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import scapy.all as scapy
import pyshark
import json
import os
from datetime import datetime
import threading
import queue

class MoxieAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Moxie Network Analyzer")
        self.setGeometry(100, 100, 800, 600)
        
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Interface selection
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_interfaces())
        layout.addWidget(QLabel("Select Network Interface:"))
        layout.addWidget(self.interface_combo)
        
        # Status display
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        layout.addWidget(QLabel("Capture Status:"))
        layout.addWidget(self.status_text)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        
        # Initialize capture thread and queue
        self.capture_thread = None
        self.message_queue = queue.Queue()
        self.is_capturing = False
        
        # Timer for updating GUI
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(100)
        
    def get_interfaces(self):
        try:
            return [iface.name for iface in scapy.get_working_ifaces()]
        except:
            return ['wlan0', 'eth0']  # Fallback interfaces

    def start_capture(self):
        self.output_dir = f"moxie_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.is_capturing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self.capture_traffic,
            args=(self.interface_combo.currentText(),)
        )
        self.capture_thread.start()
        
        self.status_text.append("Capture started...")

    def stop_capture(self):
        self.is_capturing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_text.append("Stopping capture...")
        
        # Generate report
        self.generate_report()
        
    def capture_traffic(self, interface):
        try:
            capture = pyshark.LiveCapture(
                interface=interface,
                display_filter='tcp port 443 or tcp port 80'
            )
            
            for packet in capture.sniff_continuously():
                if not self.is_capturing:
                    break
                    
                self.process_packet(packet)
                
        except Exception as e:
            self.message_queue.put(f"Error: {str(e)}")

    def process_packet(self, packet):
        try:
            if hasattr(packet, 'http') or hasattr(packet, 'ssl'):
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': 'HTTP' if hasattr(packet, 'http') else 'HTTPS',
                    'length': packet.length,
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'unknown',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else 'unknown'
                }
                
                # Save to file
                with open(f"{self.output_dir}/captured_traffic.json", 'a') as f:
                    json.dump(entry, f)
                    f.write('\n')
                
                # Update status
                self.message_queue.put(f"Captured {entry['protocol']} packet: {entry['src_ip']} -> {entry['dst_ip']}")
                
        except Exception as e:
            self.message_queue.put(f"Error processing packet: {str(e)}")

    def update_status(self):
        # Update GUI with queued messages
        try:
            while True:
                message = self.message_queue.get_nowait()
                self.status_text.append(message)
                self.status_text.verticalScrollBar().setValue(
                    self.status_text.verticalScrollBar().maximum()
                )
        except queue.Empty:
            pass

    def generate_report(self):
        try:
            with open(f"{self.output_dir}/captured_traffic.json", 'r') as f:
                packets = [json.loads(line) for line in f]
                
            report = {
                'total_packets': len(packets),
                'protocols': {
                    'HTTP': len([p for p in packets if p['protocol'] == 'HTTP']),
                    'HTTPS': len([p for p in packets if p['protocol'] == 'HTTPS'])
                },
                'unique_ips': {
                    'sources': len(set(p['src_ip'] for p in packets)),
                    'destinations': len(set(p['dst_ip'] for p in packets))
                },
                'timestamp': datetime.now().isoformat()
            }
            
            with open(f"{self.output_dir}/analysis_report.json", 'w') as f:
                json.dump(report, f, indent=2)
                
            self.status_text.append(f"\nAnalysis complete! Check {self.output_dir} for results.")
            
        except Exception as e:
            self.status_text.append(f"Error generating report: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = MoxieAnalyzerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
