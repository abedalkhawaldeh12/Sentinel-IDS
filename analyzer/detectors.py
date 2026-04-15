import time
from collections import defaultdict

# Port Scan Tracker
syn_track = defaultdict(dict)
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW = 3.0

# ARP Tracker
arp_table = {}

# ICMP Flood Tracker
icmp_track = defaultdict(list)
ICMP_FLOOD_THRESHOLD = 20
ICMP_TIME_WINDOW = 1.0

# Suspicious keywords for Payload Inspection
PAYLOAD_KEYWORDS = [b'password=', b'login', b'admin', b'user=', b'pass=']

# Known cleartext ports
CLEARTEXT_PORTS = {
    80: 'HTTP',
    21: 'FTP',
    23: 'Telnet'
}

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()
    syn_track[src_ip][dst_port] = current_time
    cleanup_old_scans(src_ip, current_time)

    if len(syn_track[src_ip]) > PORT_SCAN_THRESHOLD:
        detected_ports = list(syn_track[src_ip].keys())
        description = f"Possible SYN Port Scan detected. Targeted ports: {detected_ports}"
        syn_track[src_ip].clear()
        return description
    return None

def cleanup_old_scans(src_ip, current_time):
    ports_to_remove = [port for port, timestamp in syn_track[src_ip].items() if current_time - timestamp > TIME_WINDOW]
    for port in ports_to_remove:
        del syn_track[src_ip][port]

def detect_cleartext(dst_port):
    if dst_port in CLEARTEXT_PORTS:
        protocol = CLEARTEXT_PORTS[dst_port]
        return protocol, f"Cleartext protocol ({protocol}) in use."
    return None, None

def detect_arp_spoof(ip, mac):
    if ip in arp_table:
        if arp_table[ip] != mac:
            desc = f"ARP Spoofing Detected! IP {ip} is being claimed by MAC {mac} instead of {arp_table[ip]}."
            return desc
    else:
        arp_table[ip] = mac
    return None

def detect_icmp_flood(src_ip):
    current_time = time.time()
    icmp_track[src_ip].append(current_time)
    
    # Cleanup old pings
    icmp_track[src_ip] = [t for t in icmp_track[src_ip] if current_time - t <= ICMP_TIME_WINDOW]
    
    if len(icmp_track[src_ip]) > ICMP_FLOOD_THRESHOLD:
        desc = f"ICMP Ping Flood Detected! {len(icmp_track[src_ip])} queries in 1s."
        icmp_track[src_ip].clear()
        return desc
    return None

def inspect_payload(raw_data):
    for keyword in PAYLOAD_KEYWORDS:
        if keyword in raw_data:
            return f"Sensitive Data Leak Alert: Found '{keyword.decode('utf-8', errors='ignore')}' in plaintext payload."
    return None
