from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto_name = "ICMP"
            src_port = "-"
            dst_port = "-"
        else:
            proto_name = str(protocol)
            src_port = "-"
            dst_port = "-"

        print(f"[{proto_name}] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

print("🔍 Network Sniffer Started... Press CTRL+C to stop\n")
sniff(prn=packet_callback, store=False, count=50)