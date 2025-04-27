from scapy.all import IP, TCP, send, sniff
import threading
import time

def send_syn_packets(ip_address, port, count):
    for i in range(count):
        packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
        send(packet, verbose=False)
        print(f"SYN packet {i+1} sent to {ip_address}:{port}")
        time.sleep(0.5)

def packet_callback(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)
        # Check if it's a SYN-ACK or RST
        if tcp_layer.flags == 0x12:
            print(f"Received SYN-ACK from {ip_layer.src}:{tcp_layer.sport} (Port OPEN)")
        elif tcp_layer.flags == 0x14:
            print(f"Received RST-ACK from {ip_layer.src}:{tcp_layer.sport} (Port CLOSED)")

def start_sniffer(target_ip):
    # Sniff only packets from the target IP and TCP
    sniff(filter=f"tcp and host {target_ip}", prn=packet_callback, timeout=10)

def main():
    ip_address = input("Enter the IP address: ").strip()
    try:
        port = int(input("Enter the port number: "))
        count = int(input("Enter the number of SYN packets to send: "))
    except ValueError:
        print("Invalid input. Exiting.")
        return

    # Start the sniffer in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffer, args=(ip_address,))
    sniffer_thread.start()

    # Start sending SYN packets
    send_syn_packets(ip_address, port, count)

    # Wait for sniffer to finish
    sniffer_thread.join()

if __name__ == "__main__":
    main()
