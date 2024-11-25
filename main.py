import json
import os
from datetime import datetime
from modules.reconnaissance import scan_network
from modules.exploit_engine import exploit_php_cgi, exploit_vsftpd
from modules.detection_testing import DetectionTesting

# Directory containing scan results
RESULTS_DIR = "results/"
SCAN_RESULTS_FILE = os.path.join(RESULTS_DIR, "scan_results.json")

def parse_scan_results(scan_file, target_ip):
    """
    Reads scan results from JSON and extracts open ports for a specific target IP.
    """
    if not os.path.exists(scan_file):
        print(f"[-] Scan results file {scan_file} not found.")
        return []

    try:
        with open(scan_file, "r") as f:
            scan_results = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[-] Error reading scan results JSON: {e}")
        return []

    # Locate the target host in scan results
    for host_info in scan_results.get("hosts", []):
        if host_info.get("host") == target_ip:
            protocols = host_info.get("protocols", {})
            tcp_ports = protocols.get("tcp", [])

            # Extract open TCP ports
            open_ports = [
                port_info["port"] for port_info in tcp_ports if port_info["state"] == "open"
            ]
            return open_ports

    print(f"[-] Target IP {target_ip} not found in scan results.")
    return []

def generate_report(scan_results_file, exploitation_results_files, detection_results):
    """
    Generates a security report based on scan, exploitation, and detection results.
    """
    # Load scan results
    with open(scan_results_file, "r") as f:
        scan_results = json.load(f)

    # Set the report filename to "security_report.txt"
    report_filename = os.path.join(RESULTS_DIR, "security_report.txt")
    
    # Initialize the report content
    report_content = []
    report_content.append(f"Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report_content.append("=" * 50 + "\n\n")

    # Host Information
    report_content.append("Host Information:\n")
    for host in scan_results.get("hosts", []):
        report_content.append(f"Host: {host['host']} ({host['hostname']})\n")
        report_content.append(f"  State: {host['state']}\n")
        report_content.append("  Open Ports:\n")
        for protocol in host['protocols']['tcp']:
            if protocol['state'] == 'open':
                report_content.append(f"    Port: {protocol['port']}  Service: {protocol['service']} ({protocol['product']} {protocol['version']})\n")
        report_content.append("\n")

    # Exploitation Results
    report_content.append("=" * 50 + "\n")
    report_content.append("Exploitation Results:\n")

    processed_ports = set()

    for result_file in exploitation_results_files:
        port_number = result_file.split("_")[1]  # "21" from "port_21_results.txt"
        
        if port_number in processed_ports:
            continue
        processed_ports.add(port_number)
        
        try:
            with open(result_file, "r") as f:
                result_content = f.read()
                report_content.append(f"\n[+] Exploitation Results for Port {port_number}:\n")
                report_content.append(result_content)
                report_content.append("\n" + "=" * 50 + "\n")
        except FileNotFoundError:
            report_content.append(f"[-] No results found for {result_file}\n")

    # Detection Testing Results
    report_content.append("=" * 50 + "\n")
    report_content.append("Detection Testing Results:\n")
    for result in detection_results:
        report_content.append(f"Attack: {result['description']} - Result: {result['result']}\n")

    # Recommendations
    report_content.append("=" * 50 + "\n")
    report_content.append("Recommendations:\n")
    report_content.append("1. Patch known vulnerabilities for open services such as FTP and HTTP.\n")
    report_content.append("2. Consider implementing a Web Application Firewall (WAF) to mitigate exploits.\n")
    report_content.append("3. Regularly update all software to avoid known vulnerabilities.\n")

    # Write the report to file
    with open(report_filename, "w") as report:
        report.writelines(report_content)
    
    print(f"[+] Report generated and saved to {report_filename}")

def main():
    # Step 1: Perform reconnaissance
    print("[+] Starting reconnaissance...")
    network_range = "172.168.1.5/24"  # Example: Scan the 172.168.1.5/24 range
    ports = '80,443,21'  # Target specific ports
    scan_network(network_range, ports)

    # Step 2: Parse scan results
    target_ip = "172.168.1.5"  # Replace with actual target IP from scan results
    local_ip = "172.168.1.6"  # Your local machine's IP for reverse connections

    print(f"[+] Reading scan results for target IP: {target_ip}")
    open_ports = parse_scan_results(SCAN_RESULTS_FILE, target_ip)

    if not open_ports:
        print(f"[-] No open ports found for {target_ip}. Exiting.")
        return

    # Print scan results for debugging
    print(f"[+] Open Ports for {target_ip}: {open_ports}")

    # Check for specific open ports and trigger exploits
    if 80 in open_ports:
        print("[+] Port 80 is open. Attempting PHP CGI exploit...")
        php_cgi_results_file = os.path.join(RESULTS_DIR, "port_80_results.txt")
        exploit_php_cgi(target_ip, local_ip, php_cgi_results_file)
   
    if 21 in open_ports:
        print("[+] Port 21 is open. Attempting vsftpd exploit...")
        vsftpd_results_file = os.path.join(RESULTS_DIR, "port_21_results.txt")
        exploit_vsftpd(target_ip, local_ip, vsftpd_results_file)

    # Step 3: Run detection testing
    print("[+] Running detection testing...")
    attack_cases = [
        {"description": "FTP brute force attack on port 21", "target_port": 21},
        {"description": "SSH password guessing on port 22", "target_port": 22},
        {"description": "Telnet brute force attack on port 23", "target_port": 23},
        {"description": "SMTP DoS attack on port 25", "target_port": 25},
        {"description": "HTTP DoS attack on port 80", "target_port": 80},
    ]
    detection_tester = DetectionTesting(target_ip, attack_cases)
    detection_results = detection_tester.run_detection_tests()

    # Step 4: Generate the report
    print("[+] Generating the report...")
    exploitation_results_files = ["results/port_21_results.txt", "results/port_80_results.txt"]
    generate_report(SCAN_RESULTS_FILE, exploitation_results_files, detection_results)

if __name__ == "__main__":
    main()

