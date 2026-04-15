import sys
from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, ICMP
from colorama import init, Fore, Style
import database
import detectors

# Initialize colorama for colored console output
init(autoreset=True)

logged_alerts = set()

def packet_callback(packet):
    try:
        # A. ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2: # 'is-at' (response)
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            arp_alert = detectors.detect_arp_spoof(src_ip, src_mac)
            if arp_alert:
                alert_key = f"ARP-{src_ip}-{src_mac}"
                if alert_key not in logged_alerts:
                    print(f"{Fore.MAGENTA}[!] ARP Spoof Alert:{Style.RESET_ALL} {arp_alert}")
                    database.log_threat(src_ip, "ARP Spoofing", 0, arp_alert)
                    logged_alerts.add(alert_key)
            return

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src

        # B. ICMP Flood Detection
        if packet.haslayer(ICMP) and packet[ICMP].type == 8: # Echo request
            icmp_alert = detectors.detect_icmp_flood(src_ip)
            if icmp_alert:
                print(f"{Fore.CYAN}[!] ICMP Flood Alert:{Style.RESET_ALL} {icmp_alert}")
                database.log_threat(src_ip, "ICMP Flood", 0, icmp_alert)

        # C. TCP Analysis (Port Scan, Cleartext, Payload)
        elif packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # --- PORT SCAN DETECTION ---
            if flags == 'S':
                scan_alert = detectors.detect_port_scan(src_ip, dst_port)
                if scan_alert:
                    print(f"{Fore.RED}[!] Port Scan Detected from {src_ip}:{Style.RESET_ALL} {scan_alert}")
                    database.log_threat(src_ip, "Port Scan", 0, scan_alert)
            
            # --- CLEARTEXT & PAYLOAD INSPECTION ---
            if packet.haslayer("Raw"):
                raw_data = bytes(packet["Raw"])
                
                # Payload deep inspection
                payload_alert = detectors.inspect_payload(raw_data)
                if payload_alert:
                    alert_key = f"{src_ip}-PayloadLeak"
                    if alert_key not in logged_alerts:
                        print(f"{Fore.RED}[!] Payload Inspection Alert:{Style.RESET_ALL} {payload_alert}")
                        database.log_threat(src_ip, "Sensitive Payload", dst_port, payload_alert)
                        logged_alerts.add(alert_key)

                # Cleartext Protocol Matching
                protocol, cleartext_alert = detectors.detect_cleartext(dst_port)
                if protocol:
                    alert_key = f"{src_ip}-{dst_port}-Cleartext"
                    if alert_key not in logged_alerts:
                        print(f"{Fore.YELLOW}[!] Cleartext Protocol Detected:{Style.RESET_ALL} {src_ip} -> Port {dst_port} ({protocol})")
                        database.log_threat(src_ip, "Cleartext Protocol", dst_port, cleartext_alert)
                        logged_alerts.add(alert_key)

        # D. DNS Analysis
        elif packet.haslayer(UDP) and packet.haslayer(DNS):
            if hasattr(packet[DNS], 'qr') and packet[DNS].qr == 0 and packet[DNS].qd:
                query_name = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                suspicious_keywords = ['.ru', '.cn', 'evil', 'c2', 'ransom']
                if any(kw in query_name.lower() for kw in suspicious_keywords):
                    alert_key = f"{src_ip}-{query_name}-DNS"
                    if alert_key not in logged_alerts:
                        alert_desc = f"Suspicious DNS query: {query_name}"
                        print(f"{Fore.MAGENTA}[!] DNS Anomaly:{Style.RESET_ALL} {src_ip} queried {query_name}")
                        database.log_threat(src_ip, "DNS Anomaly", 53, alert_desc)
                        logged_alerts.add(alert_key)
                        
    except Exception as e:
        # Ignore errors internally
        pass

def start_sniffing():
    print(f"{Fore.GREEN}[*] Initializing Lightweight IDS Sniffing Engine [UPGRADED]...{Style.RESET_ALL}")
    database.init_db()
    print(f"{Fore.GREEN}[*] Database established at {database.DB_PATH}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Starting packet capture (Press Ctrl+C to stop)...{Style.RESET_ALL}")
    
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping Sniffing Engine.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        print("Note: On Windows, you may need to run Administrator/npcap.")

if __name__ == "__main__":
    start_sniffing()
