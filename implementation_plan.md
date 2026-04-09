# WAF and Network Traffic Monitor

This document outlines the implementation plan for a Web Application Firewall (WAF) and Network Intrusion Detection System that can monitor real-time traffic, analyze PCAP files, and automatically block brute-force attacks.

## User Review Required

> [!IMPORTANT]
> The application will run a packet sniffer using 'scapy' and modify Windows Firewall rules to block malicious IP addresses.
> To block brute force attacks locally on Windows, the application requires **Administrator privileges** so it can execute `netsh` firewall commands.
> Also, capturing live packets on Windows may require Npcap or WinPcap to be installed on your system.
> Please review this and confirm if you are comfortable with running the Python application as Administrator later.

## Proposed Changes

We will build the system with a Python API backend and a Vanilla HTML/JS frontend boasting a modern, premium dark-mode aesthetic.

---

### Backend (Python/FastAPI)

The backend acts as the core engine for packet capture, rule matching, alert generation, and firewall management.

#### [NEW] backend/requirements.txt
List of python dependencies like `fastapi`, `uvicorn`, `scapy`, `pyyaml`, `websockets`.

#### [NEW] backend/app.py
The main FastAPI application providing a REST API and WebSockets.
- Serves the frontend static files.
- Provides WebSocket endpoint for streaming real-time alerts and packet data to the dashboard.
- Provides REST endpoints for uploading and analyzing `.pcap` files.

#### [NEW] backend/sniffer.py
Contains a background worker leveraging `scapy` to continuously capture packets from the active network interface. It feeds packets into the rule analyzer.

#### [NEW] backend/analyzer.py
The Rule Engine. It takes raw packets (from the sniffer or PCAP files), attempts to reconstruct HTTP payloads if possible, and evaluates them against defined rules.
- Contains the **Brute Force Tracking** logic (e.g., maintaining an in-memory dictionary of connection attempts per IP).

#### [NEW] backend/blocker.py
Responsible for invoking Windows native firewall to block IPs.
- Uses `subprocess.run` to execute `netsh advfirewall firewall add rule ...` to ban an IP when the analyzer triggers a brute-force threshold block.

#### [NEW] backend/rules.yaml
A set of robust detection rules:
- **SQL Injection**: Regex patterns for common SQL payloads.
- **XSS**: Regex patterns for cross-site scripting attempts.
- **Brute Force**: Configuration thresholds (e.g., > 20 requests per 10 seconds from a single IP).

---

### Frontend (Vanilla HTML/CSS/JS)

A beautiful, premium, dynamic dashboard as requested. It will feature a rich dark aesthetic with glassmorphism effects, live charts (via a lightweight charting lib like Chart.js or just custom CSS bars), and modern typography.

#### [NEW] frontend/index.html
The main dashboard structure containing widgets for:
- Live Network Traffic Feed
- Recent Alerts & Blocked IPs
- PCAP Upload Area
- Active Rules configuration summary

#### [NEW] frontend/css/style.css
A premium Vanilla CSS stylesheet:
- Vibrant, curated color palette (e.g., neon accents against deep dark backgrounds).
- Smooth variables-driven theming.
- Micro-animations for buttons and incoming feed rows.

#### [NEW] frontend/js/main.js
Handles WebSocket connection to the backend, dynamic DOM updates for new alerts and packets, and uploading PCAP files for analysis.

## Open Questions

1. **Network Interface**: Would you like the backend to automatically pick the default network interface to sniff, or do you want a selection menu in the UI?
2. **Traffic to Monitor**: Should we default to listening only on HTTP/HTTPS ports (80, 8080, 443), or all TCP traffic?
3. **Npcap**: Do you already have Npcap (or Wireshark) installed on your Windows machine for packet sniffing? `scapy` will need this.

## Verification Plan

### Automated Tests
- Uploading a sample `.pcap` containing a simulated SQL injection to verify the analyzer triggers an alert correctly.
- Stress testing the analyzer by injecting 50 loops of dummy packet objects in Python to ensure brute-force thresholds are hit and the block function is called (simulated without actually touching `netsh` if privileges aren't available).

### Manual Verification
- We will start the FastAPI server locally.
- Access the beautiful UI.
- Use a script or a browser to quickly refresh the page or make requests to trigger the brute-force detection.
- Verify through Windows Firewall that the block rule was indeed added.
