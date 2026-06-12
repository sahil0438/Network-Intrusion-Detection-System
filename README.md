# 🛡️ NetSecure — Network Intrusion Detection & Threat Response System

A robust, web-based **Network Security** tool built with Python and Flask. NetSecure provides real-time network traffic monitoring, signature-based and behavioral intrusion detection, active firewall-level threat blocking, and forensic PCAP export — all through an intuitive web interface.

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [How to Use](#how-to-use)
- [IDS Detection Engine](#ids-detection-engine)
- [Firewall Blocking](#firewall-blocking)
- [Building the Executable](#building-the-executable)
- [Important Notes](#important-notes)
- [Credits](#credits)

---

## About

**NetSecure** is a comprehensive network security platform that bridges the gap between passive monitoring and active defense. It captures live packets from your network interface, runs them through an IDS (Intrusion Detection System) engine for signature and behavioral analysis, streams alerts to a web dashboard in real time, and can dynamically push firewall block rules for detected threats. Flagged packets are automatically exported to a `.pcap` file for forensic analysis in Wireshark.

---

## Features

### 🔍 Monitoring & Capture
- 🌐 **Live packet sniffing** on any network interface (Wi-Fi, Ethernet, etc.)
- 📂 **PCAP file upload & analysis** — analyze previously captured traffic (`.pcap` / `.pcapng`)
- 🎯 **BPF Filter support** — filter capture by protocol, IP, port (e.g. `tcp port 80`, `host 192.168.1.1`)
- 📡 **Target Domain Watchlist** — monitor specific domains and their resolved IPs
- 🖥️ **Interface dropdown** — auto-detects all available network adapters via Scapy

### 🚨 Intrusion Detection (IDS Engine)
- 🔏 **Signature-based detection** — regex pattern matching on raw packet payloads
- 🧠 **Behavioral / metadata analysis** — port scan detection, TTL anomalies, DNS flood detection, large packet flags
- 🎨 **Color-coded alerts** — purple (targeted), orange (intrusion), red (both)
- 📋 **Flagged Packets Log** — dedicated table with searchable, real-time alerts
- 📋 **All Packets Log** — complete packet history with search and filtering

### 🔒 Active Threat Response
- 🚫 **Dynamic IP blocking** — block source IPs, destination IPs, or entire domains at the firewall level
- 🐧 **Linux:** uses `iptables` / `ip6tables` (INPUT & OUTPUT chains)
- 🪟 **Windows:** uses `netsh advfirewall` firewall rules
- 🔄 **Auto-cleanup** — firewall rules are cleared automatically when capture stops
- 🌍 **IPv4 and IPv6** support for both monitoring and blocking

### 💾 Forensic Export
- 📁 **Auto-saves flagged packets** to `flagged_packets.pcap` — fully compatible with Wireshark
- 📤 **Upload & re-analyze** existing PCAP files through the same IDS pipeline

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask |
| Packet Capture | Scapy (sniff, rdpcap, wrpcap) |
| Frontend | HTML, CSS, JavaScript (Jinja2 templates) |
| Firewall Management | iptables / ip6tables (Linux), netsh (Windows) |
| Packet Capture Driver | libpcap (Linux) / Npcap (Windows) |
| Executable Packaging | PyInstaller |

---

## Project Structure

```
NetSecure/
│
├── app.py                  # Main Flask app — IDS engine, capture, blocking, API routes
│
├── templates/              # HTML Jinja2 templates (web UI)
│   └── index.html
│
├── static/                 # Frontend assets (CSS, JS)
│   ├── css/
│   └── js/
│       └── script.js
│
├── flagged_packets.pcap    # Auto-generated — flagged packets saved here
│
├── NetSecure.spec          # PyInstaller spec for building standalone executable
└── README.md
```

---

## Prerequisites

### System Requirements
- **Python 3.8+** — [Download](https://python.org)
- **pip** — comes with Python

### Packet Capture Driver (Required)
| OS | Driver | Install |
|---|---|---|
| Linux | libpcap | `sudo apt install libpcap-dev` (Debian/Ubuntu) |
| Windows | Npcap | [Download from nmap.org/npcap](https://nmap.org/npcap/) — check **"WinPcap API-compatible Mode"** during install |

### Firewall Tools (for blocking features)
| OS | Tool | Notes |
|---|---|---|
| Linux | iptables / ip6tables | Usually pre-installed |
| Windows | netsh | Built into Windows |

### ⚠️ Privileges Required
> Packet sniffing and firewall management require elevated privileges.
> - **Linux:** run with `sudo`
> - **Windows:** run as **Administrator**

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/NetSecure.git
cd NetSecure
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install flask scapy netifaces
```

---

## Running the App

### Linux (requires sudo)

```bash
sudo python3 app.py
```

### Windows (requires Administrator)

Open **Command Prompt as Administrator**, then:

```bash
python app.py
```

### Expected output

```
WARNING: You must run this Flask app as Administrator for packet capture...
* Serving Flask app 'server'
* Running on http://0.0.0.0:5000
* Running on http://127.0.0.1:5000
```

Open **http://localhost:5000** in your browser.

---

## How to Use

### Live Capture
1. Select a **network interface** from the dropdown (or choose "Any")
2. Optionally enter a **BPF filter** (e.g. `tcp port 443`)
3. Optionally add **target domains** to the watchlist
4. Click **Start Capture**
5. Monitor the **Flagged Packets Log** for alerts and the **All Packets Log** for full traffic

### PCAP Analysis
1. Click **Choose File** and select a `.pcap` or `.pcapng` file
2. Optionally add domain filters
3. Click **Analyze PCAP**
4. Results appear in both packet tables with IDS flags applied

### IP/Domain Blocking
1. Enter IPs or domains in the **Block Management** section
2. Click **Apply Blocks** — firewall rules are pushed immediately if a capture is active
3. Click **Refresh Block Status** to verify active rules
4. Rules are automatically removed when you stop the capture

### Viewing Flagged PCAP in Wireshark
1. Open **Wireshark**
2. **File → Open** → select `flagged_packets.pcap` from the project folder
3. Full forensic analysis with Wireshark's protocol dissection

---

## IDS Detection Engine

The IDS engine inside `app.py` uses two detection methods:

### Signature-Based Detection
- Compiled `re.Pattern` regex objects scan raw packet payload bytes
- Case-insensitive matching for common attack signatures (SQL injection, XSS, malware patterns, etc.)

### Behavioral / Metadata Analysis
- **Port scan detection** — tracks unique destination ports per source IP over a time window using `defaultdict` + `time.time()`
- **TTL anomaly detection** — flags unusually low or high TTL values
- **DNS flood detection** — counts DNS queries per source within time thresholds
- **Large/fragmented packet flags** — checks `packet[IP].len` against defined thresholds
- **TCP flag analysis** — detects suspicious flag combinations (e.g. SYN floods, NULL scans)

---

## Firewall Blocking

| Platform | Method | Direction |
|---|---|---|
| Linux | `iptables -A INPUT/OUTPUT -s/-d [IP] -j DROP` | INPUT (source) + OUTPUT (destination) |
| Linux IPv6 | `ip6tables -A INPUT/OUTPUT -s/-d [IP] -j DROP` | INPUT + OUTPUT |
| Windows | `netsh advfirewall firewall add rule ... action=block` | OUTPUT (destination) |

> ℹ️ On Windows, outbound (destination) blocking is fully supported. Inbound source IP blocking has OS-level limitations with `netsh`.

---

## Building the Executable

NetSecure can be packaged as a **standalone `.exe`** (Windows) using PyInstaller:

```bash
pip install pyinstaller
pyinstaller NetSecure.spec
```

The executable will be created in the `dist/` folder as `NetSecure.exe`. It bundles the Flask app, Scapy, all templates, and static files — no Python installation needed to run it.

> ⚠️ The executable still requires **Npcap** to be installed on Windows and must be run as **Administrator**.

---

## Important Notes

- Always run with **Administrator / sudo** — required for both packet capture and firewall management
- On Windows, install **Npcap** with WinPcap compatibility mode enabled
- Firewall rules applied by NetSecure are **automatically cleaned up** when you stop the capture
- The `flagged_packets.pcap` file is **overwritten** each session — back it up if needed
- This tool is intended for **authorized network monitoring only** — use responsibly on networks you own or have permission to monitor

---

## Credits

- Packet capture powered by [Scapy](https://scapy.net/)
- Web framework by [Flask](https://flask.palletsprojects.com/)
- Executable packaging by [PyInstaller](https://pyinstaller.org/)
- Inspired by [Wireshark](https://www.wireshark.org/) and open-source IDS tools
