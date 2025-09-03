
from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time

scan_attempts = defaultdict(list)   
icmp_count = defaultdict(list)      
syn_count = defaultdict(list)       

SCAN_THRESHOLD = 10        
ICMP_THRESHOLD = 20        
SYN_THRESHOLD = 30         
TIME_WINDOW = 5            


def detect_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()

        if packet.haslayer(ICMP):
            if packet[ICMP].type == 8:
                print(f"[ALERT] ICMP Echo Request (ping) from {src} to {dst}")

            icmp_count[src].append(now)
            icmp_count[src] = [t for t in icmp_count[src] if now - t <= TIME_WINDOW]
            if len(icmp_count[src]) > ICMP_THRESHOLD:
                print(f"[ALERT] ICMP Flood detected from {src}")

        if packet.haslayer(TCP):
            flags = packet[TCP].flags

            if flags == "S":
                dport = packet[TCP].dport
                print(f"[ALERT] TCP SYN attempt from {src} to {dst}:{dport}")

                scan_attempts[src].append((now, dport))
                scan_attempts[src] = [(t, p) for (t, p) in scan_attempts[src] if now - t <= TIME_WINDOW]
                unique_ports = {p for (t, p) in scan_attempts[src]}
                if len(unique_ports) > SCAN_THRESHOLD:
                    print(f"[ALERT] Port Scan detected from {src} (>{SCAN_THRESHOLD} ports in {TIME_WINDOW}s)")

                syn_count[src].append(now)
                syn_count[src] = [t for t in syn_count[src] if now - t <= TIME_WINDOW]
                if len(syn_count[src]) > SYN_THRESHOLD:
                    print(f"[ALERT] SYN Flood detected from {src}")


print("Starting Lightweight IDS...")
print("Press Ctrl+C to stop.")
sniff(prn=detect_packet, store=0)
