<div align="center">
  <h1>🛡️ Sentinel IDS & Network Monitor</h1>
  <p><b>Lightweight, Real-Time Intrusion Detection & Blue Team Defense System</b></p>

  <!-- Badges -->
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/.NET_Core-MVC-purple?style=for-the-badge&logo=dotnet" alt=".NET" />
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status" />
</div>

<br />

## 📖 Overview

**Sentinel** is an advanced yet lightweight Intrusion Detection System (IDS) and Network Traffic Monitor designed primarily for Blue Team defensive operations. It captures packets in real-time, analyzes them using Deep Packet Inspection (DPI) heuristics, and logs threats into an elegant, dark-mode web dashboard.

Whether you are monitoring a local network, studying network security, or setting up a defensive perimeter, Sentinel gives you eyes on the wire.

## ✨ Key Features

- **Port Scan Detection:** Identifies rapid `SYN` scans probing your firewall or endpoints.
- **ICMP Ping Floods:** Detects DoS attempts targeting network availability via excessive `Ping` packets.
- **ARP Spoofing Protection:** Flags Man-In-The-Middle (MITM) attacks by detecting IP-to-MAC address poisoning.
- **Cleartext Alerting:** Warns when sensitive protocols (HTTP, FTP, Telnet) are used over unencrypted channels.
- **Payload Extraction (DPI):** Deep packet inspection catches credentials (e.g., `password=`, `admin`) leaking in plain text.
- **DNS Anomalies:** Monitors requests for suspicious/malicious domains and C2 servers.
- **Glassmorphism Dashboard:** A stunning ASP.NET Core frontend providing real-time KPI metrics and threat logs.

---

## 🚀 Installation & Setup

Sentinel is cross-platform and can run on **Windows**, **Linux**, and **macOS**.

### Prerequisites
Before starting, ensure you have the following installed:
1. **Python 3.8+**
2. **.NET 8.0 SDK** (or newer)
3. **Packet Capture Libraries:**
   - **Windows:** Install [Npcap](https://npcap.com/) (Required for Scapy on Windows).
   - **Linux:** Install `tcpdump` and `libpcap-dev`.

### 🐧 Linux / macOS Installation

```bash
# 1. Clone the repository
git clone https://github.com/abedalkhawaldeh12/Sentinel-IDS.git
cd Sentinel-IDS

# 2. Install Python Dependencies
cd analyzer
sudo apt-get install tcpdump libpcap-dev  # On Debian/Ubuntu
pip3 install -r requirements.txt

# 3. Start the Analyzer Engine (Requires root/sudo for packet sniffing)
sudo python3 sniffer.py
```

### 🪟 Windows Installation

```powershell
# 1. Clone the repository
git clone https://github.com/abedalkhawaldeh12/Sentinel-IDS.git
cd Sentinel-IDS

# 2. Install Python Dependencies
cd analyzer
pip install -r requirements.txt

# 3. Start the Analyzer Engine (Must run PowerShell as Administrator)
python sniffer.py
```

---

## 🖥️ Running the Web Dashboard

While the Python Sniffer Engine is running in the background and capturing packets, you need to start the Web Dashboard to view the data.

Open a **new, standard terminal** (no root/admin required) and run:

```bash
cd dashboard/IdsDashboard
dotnet run
```

Then, open your web browser and navigate to the address shown in the terminal (usually `http://localhost:5000` or `http://localhost:5027`).

---

## 🧪 Testing the Engine

We have included a test suite that simulates malicious attacks locally so you can see the dashboard light up immediately.

Keep the **Sniffer** and **Dashboard** running, open a third terminal, and run:
```bash
cd analyzer
python test_attacks.py
```
*(Refresh your web dashboard to see the detected simulated threats!)*

---

## ⚠️ Disclaimer
**Educational and Defensive Purposes Only.** 
This software was created for network monitoring, system administration, and cyber security education. Do not use the included `test_attacks.py` on networks you do not own or have explicit permission to test.
