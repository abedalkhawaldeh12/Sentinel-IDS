import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR, ICMP, send, sr1
from colorama import init, Fore

init(autoreset=True)

TARGET_IP = "8.8.8.8"  # Using an external IP so Windows Npcap definitely catches it the outbound traffic

def test_port_scan():
    print(f"{Fore.CYAN}[*] Simulating Port Scan (Sending 6 SYN packets)...")
    for port in range(1001, 1007):
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
    print(f"{Fore.GREEN}[+] Port Scan sent.")
    time.sleep(1)

def test_cleartext():
    print(f"{Fore.CYAN}[*] Simulating Cleartext Protocol (Port 80/HTTP)...")
    pkt = IP(dst=TARGET_IP)/TCP(dport=80)/b"GET / HTTP/1.1\r\n"
    send(pkt, verbose=0)
    print(f"{Fore.GREEN}[+] Cleartext packet sent.")
    time.sleep(1)

def test_payload_leak():
    print(f"{Fore.CYAN}[*] Simulating Sensitive Payload Leak (password=...)...")
    pkt = IP(dst=TARGET_IP)/TCP(dport=443)/b"username=admin&password=secretpassword"
    send(pkt, verbose=0)
    print(f"{Fore.GREEN}[+] Payload leak packet sent.")
    time.sleep(1)

def test_dns_anomaly():
    print(f"{Fore.CYAN}[*] Simulating DNS Anomaly (Querying evil.ru)...")
    pkt = IP(dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="test-evil-c2.ru"))
    send(pkt, verbose=0)
    print(f"{Fore.GREEN}[+] DNS query sent.")
    time.sleep(1)

def test_icmp_flood():
    print(f"{Fore.CYAN}[*] Simulating ICMP Flood (Sending 25 rapid Pings)...")
    for _ in range(25):
        pkt = IP(dst=TARGET_IP)/ICMP()
        send(pkt, verbose=0)
    print(f"{Fore.GREEN}[+] ICMP Flood sent.")

if __name__ == "__main__":
    print(f"{Fore.YELLOW}--- Starting Lightweight IDS Test Suite ---")
    test_port_scan()
    test_cleartext()
    test_payload_leak()
    test_dns_anomaly()
    test_icmp_flood()
    print(f"{Fore.YELLOW}--- All tests fired. Check your Dashboard! ---")
