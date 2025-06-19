import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
import datetime
import csv

# List of known vulnerable ports (common targets)
vulnerable_ports = {
    21: "FTP (insecure)",
    23: "Telnet (unencrypted)",
    25: "SMTP (can be misconfigured)",
    69: "TFTP (no auth)",
    110: "POP3 (unencrypted)",
    139: "NetBIOS",
    445: "SMB (Windows file sharing)",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP"
}

# Function to scan individual port
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "Unknown"

            # Try grabbing banner
            banner = "No banner"
            try:
                if port == 443:  # HTTPS banner grabbing
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        banner = f"SSL Version: {ssock.version()}"
                else:
                    sock.send(b'Hello\r\n')
                    banner = sock.recv(1024).decode().strip()
            except:
                pass

            # Vulnerable port warning
            warning = vulnerable_ports.get(port, "")

            print(f"[+] Port {port} is OPEN ({service}) | {warning}")
            with open("scan_results.txt", "a") as f:
                f.write(f"Port {port} OPEN ({service}) | Banner: {banner} | {warning}\n")

            with open("scan_results.csv", "a", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([port, service, banner, warning])
        sock.close()
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")

# Main function
def main():
    print("=== ADVANCED PYTHON PORT SCANNER ===")

    target = input("Enter target IP or hostname: ")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Invalid hostname. Exiting...")
        return

    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    except ValueError:
        print("[-] Invalid port input.")
        return

    start_time = datetime.datetime.now()
    print(f"\n[*] Scanning {ip} from port {start_port} to {end_port}...\n")
    print(f"Scan started at {start_time}\n")

    # Write headers to files
    with open("scan_results.txt", "w") as f:
        f.write(f"Scan Report for {ip} | {start_time}\n{'='*60}\n")
    with open("scan_results.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Port", "Service", "Banner", "Vulnerability Warning"])

    # Multithreaded scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)

if __name__ == "__main__":
    main()
