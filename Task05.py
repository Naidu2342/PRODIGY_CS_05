from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Packet processing function
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ""
        
        # Display basic packet information
        print(f"\n[+] Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check if the packet is TCP or UDP
        if TCP in packet:
            protocol = "TCP"
            tcp_layer = packet[TCP]
            print(f"    Protocol: {protocol}")
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            protocol = "UDP"
            udp_layer = packet[UDP]
            print(f"    Protocol: {protocol}")
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")
        
        # Display packet payload data (if available)
        if packet.payload:
            print(f"    Payload: {bytes(packet.payload)}")
        else:
            print(f"    No payload data available.")
    else:
        print("Non-IP packet detected.")

# Sniffing function to start capturing packets
def start_sniffing(interface=None):
    print("Starting packet sniffing... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    print("Packet Sniffer is running...")
    print("Disclaimer: This tool is for educational purposes only. Use it responsibly and ethically.")
    print("Unauthorized interception of network traffic is illegal and punishable under law.")
    
    # Start packet sniffing (provide the interface if required, or leave as default)
    start_sniffing(interface=None)
  
