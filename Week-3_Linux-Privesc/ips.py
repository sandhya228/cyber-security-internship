from scapy.all import sniff, IP, TCP, ICMP
import os
from collections import defaultdict
import time

packet_count = defaultdict(int)
last_time = defaultdict(float)

ICMP_THRESHOLD = 20      
SYN_THRESHOLD = 30       
BLOCK_TIME = 60          

blocked_ips = {}

def block_ip(ip):
    if ip not in blocked_ips:
        print(f"[!] Blocking IP: {ip}")
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        blocked_ips[ip] = time.time()

def unblock_ips():
    current = time.time()
    for ip in list(blocked_ips.keys()):
        if current - blocked_ips[ip] > BLOCK_TIME:
            print(f"[+] Unblocking IP: {ip}")
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            del blocked_ips[ip]

def detect(packet):
    if IP in packet:  # check if packet has IP layer
        src_ip = packet[IP].src   # <-- define src_ip here
        current_time = time.time()

        if current_time - last_time[src_ip] > 5:
            packet_count[src_ip] = 0
            last_time[src_ip] = current_time

        packet_count[src_ip] += 1

        if ICMP in packet and packet_count[src_ip] > ICMP_THRESHOLD:
            print(f"[!] ICMP flood detected from {src_ip}")
            block_ip(src_ip)

        if TCP in packet and packet[TCP].flags == "S":
            if packet_count[src_ip] > SYN_THRESHOLD:
                print(f"[!] SYN flood detected from {src_ip}")
                block_ip(src_ip)

        if TCP in packet and packet.haslayer("Raw"):
            payload = str(packet["Raw"].load).lower()
            if "union select" in payload or "drop table" in payload:
                print(f"[!] SQL injection attempt detected from {src_ip}")
                block_ip(src_ip)

    unblock_ips()


if __name__ == "__main__":
    print("[*] Starting IPS... Press CTRL+C to stop")
    sniff(prn=detect, store=0)
