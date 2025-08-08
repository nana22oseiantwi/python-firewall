# python-firewall
BLOCKED_PORTS = [23, 445, 3389]  # Telnet, SMB, RDP (example)

def log_packet(message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}")

def packet_filter(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # the IP is blocked
        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            log_packet(f"BLOCKED IP: {src_ip} -> {dst_ip}")
            return

        # packet has TCP/UDP and ports are blocked
        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport

            if sport in BLOCKED_PORTS or dport in BLOCKED_PORTS:
                log_packet(f"BLOCKED PORT: {src_ip}:{sport} -> {dst_ip}:{dport}")
                return

        # not blocked
        log_packet(f"ALLOWED: {src_ip} -> {dst_ip}")

def main():
    print("Simple Python Firewall is running... (Press Ctrl+C to stop)")
    try:
        sniff(filter="ip", prn=packet_filter, store=0)
    except KeyboardInterrupt:
        print("\nFirewall stopped by user.")

if __name__ == "__main__":
    main()
