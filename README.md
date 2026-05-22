# NetSentinel - Network Anomaly & Risk Detection Dashboard

NetSentinel is a Python-based network security dashboard that uses Nmap to scan authorized IP addresses or subnets, detect open ports and services, classify risk levels, compare results against a baseline, and generate security reports.

## Features

- Login-protected Flask dashboard
- Authorized IP/subnet scanning with Nmap
- Open port and service detection
- Baseline creation on first scan
- Anomaly detection for new hosts, protocols, and ports
- Risk classification engine for common exposed services
- SQLite scan history
- Downloadable TXT security reports
- Dashboard cards and risk chart

## Tech Stack

- Python
- Flask
- SQLite
- Nmap / python-nmap
- HTML, CSS, Bootstrap
- Chart.js

## Installation

Install Nmap first:

- Windows: Install Nmap from the official installer and make sure it is added to PATH.
- Linux: `sudo apt install nmap`
- macOS: `brew install nmap`

Then run:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Demo login:

```text
Username: admin
Password: admin123
```

You can change login credentials with environment variables:

```bash
set NETSENTINEL_USER=youruser
set NETSENTINEL_PASS=yourpass
```

## Safe Usage

Use this tool only on networks and systems you own or have explicit permission to test.

## CV Description

**NetSentinel – Network Anomaly & Risk Detection Dashboard**

Built a Python-based network security dashboard using Nmap, Flask, SQLite, and Bootstrap. The system scans authorized networks, detects open ports and services, creates a baseline of known hosts, identifies new devices or newly exposed ports, classifies risks, stores scan history, and generates downloadable security reports.
