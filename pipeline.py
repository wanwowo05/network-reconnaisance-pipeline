import socket
import subprocess
import concurrent.futures
from datetime import datetime

# The ports we care about most
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 5556]

def ping_host(ip):
    """Phase 1: Checks if an IP is active."""
    command = ['ping', '-n', '1', '-w', '500', ip]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        return ip
    return None

def scan_ports(ip):
    """Phase 2: Scans common ports on a single active IP."""
    open_ports = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Custom"
            open_ports.append(f"Port {port} ({service})")
        s.close()
    return ip, open_ports

def main():
    network_prefix = input("Enter the network prefix to scan (e.g., 192.168.0): ")
    
    print("\n" + "=" * 50)
    print(f"AUTOMATED RECONNAISSANCE PIPELINE")
    print(f"Target Network: {network_prefix}.X")
    print(f"Start Time: {datetime.now()}")
    print("=" * 50)
    
    # --- PHASE 1: DISCOVERY ---
    print("\n[+] PHASE 1: Discovering active hosts (Ping Sweep)...")
    active_hosts = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        ips_to_scan = [f"{network_prefix}.{i}" for i in range(1, 255)]
        results = executor.map(ping_host, ips_to_scan)
        
        for result in results:
            if result:
                print(f"    -> Found active device: {result}")
                active_hosts.append(result)

    if not active_hosts:
        print("\n[-] No active hosts found. Exiting pipeline.")
        return

    # --- PHASE 2: ENUMERATION ---
    print(f"\n[+] PHASE 2: Scanning ports on {len(active_hosts)} active hosts...")
    report = {}
    
    for host in active_hosts:
        print(f"    -> Scanning {host}...")
        ip, open_ports = scan_ports(host)
        if open_ports:
            report[ip] = open_ports
        else:
            report[ip] = ["No open ports detected"]

    # --- PHASE 3: REPORTING ---
    print("\n" + "=" * 50)
    print("FINAL RECONNAISSANCE REPORT")
    print("=" * 50)
    
    for host, ports in report.items():
        print(f"\nHost: {host}")
        for p in ports:
            print(f"  - {p}")

    print("\n[+] Pipeline completed successfully!")

if __name__ == "__main__":
    main()