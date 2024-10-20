# PRODIGY_CS_05
# Packet Sniffer

This project is a simple packet sniffer built using Python and the Scapy library. It captures network packets and displays basic information, including the source and destination IP addresses, protocol type (TCP/UDP), port numbers, and payload data if available. This tool is intended for educational purposes, such as learning about network protocols and traffic analysis.

# Disclaimer
- **Important:** This packet sniffer should only be used in a lawful and ethical manner. Unauthorized interception of network traffic may be illegal and could result in penalties or criminal charges. Use this tool only on networks you own or have permission to monitor.

### Requirements
- Python 3.x
- Scapy library

### Installation

1. **Install Python:** Ensure you have Python 3.x installed on your system. You can download it from the official [Python website](https://www.python.org/downloads/).

2. **Install Scapy:** Use the following command to install Scapy:
   ```bash
   pip install scapy
   ```

### Usage

1. **Run the Script:** Execute the script using a terminal or command prompt:
   ```bash
   python packet_sniffer.py
   ```
   
2. **Optional - Specify a Network Interface:** By default, the script will sniff on all available network interfaces. To specify a particular interface, modify the `start_sniffing` function call:
   ```python
   start_sniffing(interface="eth0")  # Replace "eth0" with your interface name
   ```

3. **Stop the Sniffer:** The sniffer runs indefinitely until you manually stop it. Press `Ctrl+C` to stop the packet capturing process.

### Code Overview

- **`packet_callback(packet)` Function:** 
  - Processes each captured packet.
  - Displays the source and destination IP addresses.
  - Identifies the protocol (TCP/UDP) and prints relevant information like source and destination ports.
  - Prints the packet payload if available.
  - Logs a message if a non-IP packet is detected.

- **`start_sniffing(interface=None)` Function:** 
  - Starts the packet-sniffing process using the specified network interface.
  - Uses Scapy's `sniff()` function to capture packets in real time.
  - Calls the `packet_callback()` function for each captured packet.

### Features

- **Captures Network Packets:** Supports sniffing IP-based traffic.
- **Supports TCP and UDP Protocols:** Identifies and displays details for TCP/UDP packets.
- **Displays Payload Data:** Shows packet payload if present.
- **Cross-Platform Compatibility:** Works on multiple operating systems, including Windows, Linux, and macOS (with appropriate network interface configurations).

### Limitations

- **Non-IP Packets:** The script currently only handles IP-based packets.
- **Root/Administrator Privileges:** Packet sniffing may require elevated privileges. Run the script as an administrator or use `sudo` on Unix-based systems.

### Notes

- Scapy is a powerful library for network packet manipulation and analysis but requires basic networking knowledge.
- Always ensure you have permission to monitor network traffic on the target network.

### Legal Disclaimer

This tool is intended strictly for educational purposes. The author is not responsible for any misuse or illegal use of this tool. Network monitoring without authorization is illegal in many jurisdictions.
