import sys
import importlib
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                               QLineEdit, QTableWidget, QTableWidgetItem, QTextEdit, QComboBox, QSlider)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Import the run_xss_scanner function from the module
from modules.xss import run_xss_scanner

class VulnerabilityScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(" LipSec Vulnerability Scanner 🚀")
        self.setStyleSheet(self.get_stylesheet())
        self.setMinimumSize(900, 600)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # Main content
        content_layout = QHBoxLayout()
        logo_label = QLabel("🛡️LipSec")
        logo_label.setFont(QFont("Cascadia Code", 20, QFont.Bold))
        content_layout.addWidget(logo_label)
        web_layout = QHBoxLayout()

        # New dropdown menu
        self.user_type_combo = QComboBox()
        self.user_type_combo.setPlaceholderText("Choose Scanner")
        self.user_type_combo.addItems(["XSS", "SQLi", "OR", "LFI"])
        self.user_type_combo.setFixedWidth(125)
        self.user_type_combo.setFixedHeight(30)

        # Set stylesheet for the QComboBox
        self.user_type_combo.setStyleSheet("""
            QComboBox {
                background-color: #333;
                border: 2px solid green;
                border-radius: 5px;
            }
            QComboBox::item {
                background-color: white;
                color: black;
            }
            QComboBox::item:selected {
                background-color: lightgrey;
            }
        """)
        content_layout.addWidget(self.user_type_combo)

        self.web_input = QLineEdit()
        self.web_input.setPlaceholderText("https://example.com/search?query=")
        self.web_input.setFixedWidth(400)
        listen_button = QPushButton("Scan")
        listen_button.setFixedWidth(130)
        listen_button.clicked.connect(self.run_scan)  # Connect button to run_scan method
        web_layout.addWidget(self.web_input)
        web_layout.addWidget(listen_button)
        content_layout.addLayout(web_layout)
        main_layout.addLayout(content_layout)

        # Slider for selecting number of threads
        slider_layout = QHBoxLayout()
        self.slider_label = QLabel("Threads: 1")
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setMinimum(1)
        self.slider.setMaximum(10)
        self.slider.setValue(1)
        self.slider.valueChanged.connect(self.update_slider_label)

        # Set slider width and label
        slider_layout.addWidget(self.slider_label)
        slider_layout.addWidget(self.slider)
        main_layout.addLayout(slider_layout)

        # Table
        table = QTableWidget(1, 6)
        table.setHorizontalHeaderLabels(["VulnType", "Low", "Medium", "High", "Critical", "Endpoint"])
        table.setItem(0, 0, QTableWidgetItem("XSS"))
        table.setItem(0, 1, QTableWidgetItem("1"))
        table.setItem(0, 2, QTableWidgetItem("3"))
        table.setItem(0, 3, QTableWidgetItem("0"))
        table.setItem(0, 4, QTableWidgetItem("1"))
        table.setItem(0, 5, QTableWidgetItem("https://example.com/search?q='alert(1)'"))
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        main_layout.addWidget(table)

        open_lab_button = QPushButton("Generate HTML Report")
        main_layout.addWidget(open_lab_button)

        # Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        main_layout.addWidget(self.console)

    def update_slider_label(self, value):
        """Update the label to show the number of threads based on the slider."""
        self.slider_label.setText(f"Threads: {value}")

    def run_scan(self):
        selected_scanner = self.user_type_combo.currentText()  # Get scanner type
        domain = self.web_input.text()
        num_threads = self.slider.value()  # Get number of threads from the slider

        if not domain:
            self.console.append("Please enter a domain to scan.")
            return

        # Use ThreadPoolExecutor for managing threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for _ in range(num_threads):
                executor.submit(self.scan_worker, domain, selected_scanner)

        try:
            # Dynamically import the module based on the selection
            module = importlib.import_module(f'modules.{selected_scanner.lower()}')  # Use lowercase
            logs = module.scan(domain)  # Call the scan function

            # Display the logs in the console
            self.console.append(logs)
        except ImportError:
            self.console.append(f"Error: Module '{selected_scanner}' not found.")
        except Exception as e:
            self.console.append(f"Error: {str(e)}")

    def scan_worker(self, domain, scanner_type):
        """Placeholder method to simulate scanning."""
        self.console.append(f"Scanning {domain} for {scanner_type} vulnerabilities...")

    def get_stylesheet(self):
        return """
        QWidget {
            font-family: 'Courier New', Courier, monospace;
            background-color: #0d0d0d;
            color: #33ff33;
        }
        QMainWindow {
            background-color: #1a1a1a;
        }
        QLineEdit {
            background-color: #333;
            color: #0f0;
            border: 1px solid #0f0;
            border-radius: 5px;
            padding: 5px;
        }
        QPushButton {
            background-color: #00ff00;
            color: #000;
            border: 1px solid #0f0;
            border-radius: 5px;
            padding: 5px 10px;
        }
        QPushButton:hover {
            background-color: #00cc00;
        }
        QTableWidget {
            background-color: #333;
            color: #0f0;
            border: 1px solid #00ff00;
            border-radius: 5px;
        }
        QTextEdit {
            background-color: #1e1e1e;
            color: #00ff00;
            border: 1px solid #00ff00;
            border-radius: 5px;
        }
        QSlider::groove:horizontal {
            background-color: #333;
            height: 6px;
        }
        QSlider::handle:horizontal {
            background-color: #00ff00;
            border: 1px solid #0f0;
            width: 15px;
            margin: -5px 0;
        }
        QLabel {
            color: #00ff00;
        }
        """

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VulnerabilityScanner()
    window.show()
    sys.exit(app.exec())
