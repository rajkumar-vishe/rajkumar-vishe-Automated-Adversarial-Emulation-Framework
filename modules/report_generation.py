import json
import os

# Use the existing "results" directory for saving the report
RESULTS_DIR = "results/"
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

def generate_report(scan_results_file, exploitation_results_files):
    """
    Generates a security report based on scan and exploitation results.
    """
    # Load scan results
    with open(scan_results_file, "r") as f:
        scan_results = json.load(f)

    # Create the report filename in the 'results' directory
    report_filename = os.path.join(RESULTS_DIR, "security_report.txt")
    
    # Initialize the report content
    report_content = []
    report_content.append(f"Security Report\n")
    report_content.append("=" * 50 + "\n\n")

    # Host Information
    report_content.append("Host Information:\n")
    for host in scan_results.get("hosts", []):
        report_content.append(f"Host: {host.get('host')} ({host.get('hostname')})\n")
        report_content.append(f"  State: {host.get('state')}\n")
        report_content.append("  Open Ports:\n")
        for protocol in host.get("protocols", {}).get("tcp", []):
            if protocol.get('state') == 'open':
                report_content.append(f"    Port: {protocol.get('port')}  Service: {protocol.get('service')} ({protocol.get('product')} {protocol.get('version')})\n")
        report_content.append("\n")

    # Exploitation Results
    report_content.append("=" * 50 + "\n")
    report_content.append("Exploitation Results:\n")
    
    # Loop through each exploitation result file and append the content
    for result_file in exploitation_results_files:
        try:
            with open(result_file, "r") as f:
                result_content = f.read()
                report_content.append(f"Results from {result_file}:\n")
                report_content.append(result_content)
                report_content.append("\n")
        except FileNotFoundError:
            report_content.append(f"[-] No results found for {result_file}\n")
    
    # Recommendations (basic example)
    report_content.append("=" * 50 + "\n")
    report_content.append("Recommendations:\n")
    report_content.append("1. Patch known vulnerabilities for open services such as FTP and HTTP.\n")
    report_content.append("2. Consider implementing a Web Application Firewall (WAF) to mitigate exploits.\n")
    report_content.append("3. Regularly update all software to avoid known vulnerabilities.\n")

    # Write the report to file
    with open(report_filename, "w") as report:
        report.writelines(report_content)
    
    print(f"[+] Report generated and saved to {report_filename}")

# Example usage
exploitation_results_files = ["results/port_21_results.txt", "results/port_80_results.txt"]
generate_report("results/scan_results.json", exploitation_results_files)

