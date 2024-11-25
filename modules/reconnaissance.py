import nmap
import dns.resolver
import whois
import datetime
import os
import ipaddress
import json
import shutil

# Initialize Nmap PortScanner
nm = nmap.PortScanner()

def ensure_output_directory(path):
    """
    Ensures the output directory exists.
    """
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def is_valid_ip(ip):
    """
    Validates the IP address or network range.
    """
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    """
    Checks if an IP is in a private range.
    """
    return ipaddress.ip_address(ip).is_private

def scan_network(network_range, ports='', output_file='results/scan_results.json'):
    """
    Scans the specified network range for active hosts and open ports.
    """
    if not is_valid_ip(network_range):
        print(f"Invalid IP range or network: {network_range}")
        return

    # Ensure output directory exists
    ensure_output_directory(output_file)

    # Check if the result file already exists
    if os.path.exists(output_file):
        # Move the old scan result to history (optionally, with a timestamp)
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        history_file = f"results/history_scan_{timestamp}.json"
        shutil.move(output_file, history_file)
        print(f"Previous scan result moved to history: {history_file}")

    print(f"Starting scan on network: {network_range}")

    # Set scan arguments
    scan_arguments = '-sS -sV -O'  # SYN scan, version detection, and OS detection
    if ports:
        scan_arguments += f' -p {ports}'  # Scan specified ports if provided

    try:
        # Perform the scan
        print(f"Executing Nmap scan with command: sudo nmap {scan_arguments} {network_range}")
        nm.scan(hosts=network_range, arguments=scan_arguments)

        # Debugging: Show Nmap command and scan info
        print("Nmap Command Line:", nm.command_line())
        print("Nmap Scan Info:", nm.scaninfo())

    except nmap.nmap.PortScannerError as e:
        print(f"PortScannerError: {e}")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # Prepare structured output
    scan_data = {
        "scan_metadata": {
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "network_range": network_range,
            "ports": ports
        },
        "hosts": []
    }

    for host in nm.all_hosts():
        host_data = {
            "host": host,
            "hostname": nm[host].hostname() if nm[host].hostname() else "Unknown",
            "state": nm[host].state(),
            "protocols": {},
            "additional_info": get_additional_info(host)  # Add DNS and WHOIS info here
        }

        for proto in nm[host].all_protocols():
            protocol_data = []
            for port in nm[host][proto].keys():
                service_info = nm[host][proto][port]
                protocol_data.append({
                    "port": port,
                    "state": service_info['state'],
                    "service": service_info['name'],
                    "product": service_info.get('product', 'Unknown'),
                    "version": service_info.get('version', 'Unknown'),
                    "extra_info": service_info.get('extrainfo', 'None')
                })
            host_data["protocols"][proto] = protocol_data

        scan_data["hosts"].append(host_data)

    # Save scan results to the output file (latest scan)
    with open(output_file, 'w') as file:
        json.dump(scan_data, file, indent=4)

    print(f"\nSummary: Scanned {len(nm.all_hosts())} hosts. Results saved to {output_file}.")

    # Save results in text format for compatibility
    text_output_file = 'results/scan_results.txt'
    with open(text_output_file, 'w') as txt_file:
        for host in nm.all_hosts():
            txt_file.write(f"Host: {host}\n")
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    service = nm[host][proto][port]
                    txt_file.write(f"  Port: {port}\tState: {service['state']}\tService: {service['name']}\n")
    print(f"Text results saved to {text_output_file}")

def get_additional_info(host):
    """
    Gets additional information like DNS and WHOIS data for the host.
    """
    additional_info = {}

    # DNS Resolution
    try:
        dns_info = dns.resolver.resolve(host, 'A')  # Get A record for IP addresses
        dns_ips = [str(ip) for ip in dns_info]
        additional_info["dns"] = dns_ips
        print(f"DNS Information for {host}: {dns_ips}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        additional_info["dns"] = f"No DNS records found: {e}"
        print(f"  No DNS records found: {e}")

    # WHOIS Information
    try:
        whois_info = whois.whois(host)
        whois_data = {key: value for key, value in whois_info.items()}
        additional_info["whois"] = whois_data
        print(f"WHOIS Information for {host}: {whois_data}")
    except Exception as e:
        additional_info["whois"] = f"WHOIS lookup failed: {e}"
        print(f"  WHOIS lookup failed: {e}")

    return additional_info
