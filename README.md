# SSL/TLS Master Auditor (v2026)

A professional-grade SSL/TLS configuration and certificate analysis tool designed for penetration testers and GRC auditors. This script automates the discovery of weak encryption standards, deprecated protocols, and certificate vulnerabilities across multiple domains.

## 🚀 Features

- **Protocol Analysis:** Detects support for SSL 2.0, 3.0 and TLS 1.0, 1.1, 1.2, 1.3.
- **Cipher Suite Auditing:** Identifies and flags weak ciphers (RC4, 3DES, CBC, MD5, SHA1).
- **Certificate Intelligence:** Detects Wildcard certificates (*), Key Size, and Signature Algorithms.
- **Vulnerability Scanning:** Dedicated check for the Heartbleed vulnerability.
- **Automated Reporting:** Generates a detailed, well-organized `.xlsx` report with auto-adjusted column widths for easy sharing.

## 🛠️ Prerequisites

This tool is optimized for **Kali Linux** using Python 3.13+. It is recommended to run this within a virtual environment to avoid conflicts with system-level packages.

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install sslyze pandas openpyxl

📋 Usage
Open ssl_audit_v4.py.

Update the target_domains list with your scope.

Run the auditor:

# python3 ssl_audit_v4.py

The script will output a file named full_ssl_pentest_report.xlsx in the root directory.

🛡️ Security Use Cases
Compliance Audits: Quickly identify PCI-DSS or SOC2 violations (e.g., use of TLS 1.0).

Reconnaissance: Map the attack surface by identifying wildcard certificates and shared infrastructure.

Vulnerability Management: Identify servers susceptible to Man-in-the-Middle (MITM) attacks due to weak cipher suites.
