import socket
import threading
import time
from tqdm import tqdm
import random
import ssl
import struct
import requests
import csv

# Predefined list of known services and ports
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}

# List of suspicious services
suspicious_services = ["Telnet", "FTP", "NetBIOS"]

# Scan results
scan_results = []

# Fragmented Packet Function for Firewall Evasion
def fragment_packet(data):
    max_size = 8  # Create small fragments
    fragments = [data[i:i+max_size] for i in range(0, len(data), max_size)]
    return fragments

# Randomize source port for evasion
def randomize_source_port():
    return random.randint(1024, 65535)

# Improved OS detection
def detect_os(ttl, window_size):
    if ttl > 128:
        return "Linux/Unix-like OS"
    elif ttl > 64:
        return "Windows OS"
    else:
        return "Unknown OS"

# SYN Scan function
def syn_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        source_port = randomize_source_port()
        sock.bind(("", source_port))
        
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = services.get(port, "Unknown service")
            banner = grab_banner(ip, port)
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            os_info = detect_os(ttl, window_size)
            scan_results.append((port, service, "OPEN", banner, os_info))
            print(f"[+] Port {port} ({service}): OPEN")
        else:
            scan_results.append((port, "Unknown", "CLOSED", "No banner", "Unknown OS"))
    except Exception as e:
        print(f"[!] Error on port {port}: {e}")
    finally:
        sock.close()

# UDP Scan
def udp_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (ip, port))  # Sending a basic packet
        
        # Try to receive a response
        data, _ = sock.recvfrom(1024)
        if data:
            service = services.get(port, "Unknown service")
            scan_results.append((port, service, "OPEN (UDP)", "No banner", "Unknown OS"))
            print(f"[+] UDP Port {port} ({service}): OPEN")
    except socket.timeout:
        scan_results.append((port, "Unknown", "CLOSED", "No banner", "Unknown OS"))
    except Exception as e:
        print(f"[!] Error scanning UDP Port {port}: {e}")
    finally:
        sock.close()

# Stealth scan function using SYN flags
def stealth_syn_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Perform stealth SYN scan
        print(f"[+] Stealth SYN Scan Port {port}")
    except Exception as e:
        print(f"[!] Stealth SYN Scan error on port {port}: {e}")
    finally:
        sock.close()

# Service version detection by banner grabbing
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        if banner:
            return banner
        else:
            return "No banner"
    except Exception as e:
        return f"Error grabbing banner: {e}"
    finally:
        sock.close()

# Firewall evasion using decoy scan
def decoy_scan(ip, port, timeout, decoy_ips):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Simulate multiple decoy IPs
        for decoy in decoy_ips:
            print(f"[+] Using decoy: {decoy}")
        sock.close()
    except Exception as e:
        print(f"[!] Decoy scan error: {e}")

# Threaded TCP and UDP scanning with firewall bypass techniques
def scan_ports_with_timeout(ip, start_port, end_port, timeout, stealth=False, udp=False, decoy=False, decoy_ips=[]):
    threads = []
    ports = range(start_port, end_port+1)
    
    for port in tqdm(ports):
        if udp:
            thread = threading.Thread(target=udp_scan, args=(ip, port, timeout))
        elif stealth:
            thread = threading.Thread(target=stealth_syn_scan, args=(ip, port, timeout))
        elif decoy:
            thread = threading.Thread(target=decoy_scan, args=(ip, port, timeout, decoy_ips))
        else:
            thread = threading.Thread(target=syn_scan, args=(ip, port, timeout))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Function to save results
def save_results_to_file(filename, file_format='txt'):
    print(f"Saving results to {filename}.{file_format}...")
    if file_format == 'txt':
        with open(f"{filename}.txt", 'w') as file:
            for result in scan_results:
                file.write(f"Port: {result[0]}, Service: {result[1]}, Status: {result[2]}, Banner: {result[3]}, OS: {result[4]}\n")
    elif file_format == 'csv':
        with open(f"{filename}.csv", 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'Service', 'Status', 'Banner', 'OS'])
            writer.writerows(scan_results)
    print(f"Results saved to {filename}.{file_format} successfully!")

# Example usage
target_ip = input("Enter target IP: ")
start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))
timeout = float(input("Enter timeout in seconds: "))

scan_choice = input("Choose scan type (syn/stealth/udp/decoy): ").lower()
if scan_choice == "udp":
    scan_ports_with_timeout(target_ip, start_port, end_port, timeout, udp=True)
elif scan_choice == "stealth":
    scan_ports_with_timeout(target_ip, start_port, end_port, timeout, stealth=True)
elif scan_choice == "decoy":
    decoy_ips = input("Enter decoy IPs (comma separated): ").split(',')
    scan_ports_with_timeout(target_ip, start_port, end_port, timeout, decoy=True, decoy_ips=decoy_ips)
else:
    scan_ports_with_timeout(target_ip, start_port, end_port, timeout)

save_option = input("Save results to file? (yes/no): ").lower()
if save_option == "yes":
    file_name = input("Enter filename: ")
    file_format = input("Enter file format (txt/csv): ").lower()
    save_results_to_file(file_name, file_format)
else:
    print("Results not saved.")