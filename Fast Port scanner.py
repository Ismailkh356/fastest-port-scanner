import socket
import threading
from tqdm import tqdm
import csv
import random
import ssl
import requests

# Common ports and services dictionary
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
}

# List of suspicious services
suspicious_services = ["Telnet", "FTP","SSH", "Telnet", "SMTP"]

# Initialize an empty list to store scan results
scan_results = []

# Function to handle HTTP/HTTPS banner grabbing
def http_banner_grab(ip, port):
    try:
        if port == 80:  # HTTP
            response = requests.get(f'http://{ip}', timeout=3)
            if response:
                banner = response.headers.get('Server', 'No Server Info')
                return banner
        elif port == 443:  # HTTPS
            # Disable SSL verification for banner grabbing
            context = ssl._create_unverified_context()
            with socket.create_connection((ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    banner = cert.get('subject', 'No Certificate Info')
                    return str(banner)
    except Exception as e:
        return f"Error grabbing banner: {e}"
    return "No banner"

# Improved banner grabbing with retries and special cases for HTTP/HTTPS
def grab_banner(ip, port):
    sock = None  # Initialize the sock variable here
    try:
        # Special handling for HTTP and HTTPS
        if port == 80 or port == 443:
            return http_banner_grab(ip, port)
        
        # General banner grabbing for other ports
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
        if sock:
            sock.close()

# TCP SYN Scan function using raw sockets (requires elevated privileges)
def syn_scan(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Send SYN packet
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = services.get(port, "Unknown service")
            print(f"[+] Port {port} ({service}): OPEN")
            
            # Grab banner for the open port
            banner = grab_banner(ip, port)
            print(f"[+] Banner for Port {port}: {banner}")
            
            # Check if the service is suspicious
            if service in suspicious_services:
                print(f"[!] Suspicious Service Detected on Port {port} ({service})")
            
            # Append results to scan_results
            scan_results.append((port, service, "OPEN", banner))
        else:
            print(f"[-] Port {port}: CLOSED")
            scan_results.append((port, "Unknown", "CLOSED", "No banner"))
    except Exception as e:
        print(f"[!] Error scanning Port {port}: {e}")
        scan_results.append((port, "Unknown", "ERROR", str(e)))
    finally:
        if sock:
            sock.close()

# Function to randomize the order of port scans
def random_port_order(start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    return ports

def scan_ports_with_timeout(ip, start_port, end_port, timeout, syn_scan_enabled=False):
    threads = []
    print(f"Scanning {ip} for open ports, services, and banners from {start_port} to {end_port} with a timeout of {timeout} seconds...")
    
    # Randomize the port order to avoid detection
    ports_to_scan = random_port_order(start_port, end_port)

    # Add a progress bar using tqdm
    for port in tqdm(ports_to_scan):
        thread = threading.Thread(target=syn_scan, args=(ip, port, timeout))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def save_results_to_file(filename, file_format='txt'):
    print(f"\n[+] Saving results to {filename}.{file_format}...")
    if file_format == 'txt':
        with open(f"{filename}.txt", 'w') as file:
            for result in scan_results:
                file.write(f"Port: {result[0]}, Service: {result[1]}, Status: {result[2]}, Banner: {result[3]}\n")
    elif file_format == 'csv':
        with open(f"{filename}.csv", 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'Service', 'Status', 'Banner'])
            writer.writerows(scan_results)
    print(f"[+] Results saved to {filename}.{file_format} successfully!")

# Example usage
target_ip = input("Enter target IP: ")
start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))
timeout = float(input("Enter the timeout in seconds: "))
scan_ports_with_timeout(target_ip, start_port, end_port, timeout)

# Ask user if they want to save the results
save_option = input("Do you want to save the results? (yes/no): ").lower()
if save_option == "yes":
    file_name = input("Enter the filename: ")
    file_format = input("Enter file format (txt/csv): ").lower()
    save_results_to_file(file_name, file_format)
else:
    print("[!] Results not saved.")