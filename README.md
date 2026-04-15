# Sentinel - Lightweight IDS & Network Monitor 🛡️

Sentinel is a lightweight Intrusion Detection System (IDS) and Real-Time Network Monitor built focusing on defense (Blue Team). It integrates a powerful Python sniffing engine (Scapy) with an elegant, "glassmorphism"-styled ASP.NET Core MVC Web Dashboard.

## Features
- **Real-Time Packet Sniffing**: Analyzes TCP, UDP, and ICMP traffic seamlessly.
- **Advanced Threat Detection**:
  - `Port Scans`: Detects rapid SYN scans across multiple ports.
  - `ICMP Ping Floods`: Detects high-volume ICMP echo requests indicating a DoS.
  - `ARP Spoofing`: Flags Man-In-The-Middle attacks via MAC address spoofing.
  - `Cleartext Traffic`: Identifies plaintext usages of FTP, Telnet, or HTTP.
  - `Sensitive Payload Leak`: Deep Packet Inspection (DPI) catching credentials (`password=`, `admin`) over plaintext.
  - `DNS Anomalies`: Warns locally generated connections against C2 servers or suspicious domains.
- **Live Dark-Mode Dashboard**: Interactive `.NET Core` UI displaying statistics, charts, and actionable raw logs.

## Technology Stack
- **Analyzer Engine**: Python 3.x, `Scapy`, `Colorama`
- **Web App**: ASP.NET Core MVC (C#), HTML/CSS
- **Database Architecture**: SQLite via Entity Framework (EF) Core

## How to Run locally

### 1) Start the Sniffer Engine (⚠️ Requires Administrator)
Open a terminal as Administrator and execute:
```bash
cd analyzer
pip install -r requirements.txt
python sniffer.py
```

### 2) Start the Web Dashboard
Open a secondary standard terminal and execute:
```bash
cd dashboard/IdsDashboard
dotnet run
```
Navigate to `http://localhost:<PORT>` shown in your terminal.

## Architecture Directory Structure
- `/analyzer/`: Contains Python engine scripts and simulated attack suite.
- `/dashboard/`: Contains the ASP.NET Core MVC frontend framework.
