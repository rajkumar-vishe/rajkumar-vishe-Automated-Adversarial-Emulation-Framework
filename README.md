# Automated Adversarial Emulation Framework  

## Overview  
The **Automated Adversarial Emulation Framework** is an open-source project designed to automate red team cybersecurity operations. It includes modules for network reconnaissance, exploiting vulnerabilities, testing detection mechanisms, and generating detailed security reports. This project helps security professionals simulate attacks and test the effectiveness of security defenses.  

## Table of Contents  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Modules](#modules)
- [Disclaimer](#disclaimer)
- [License](#license)  

## Prerequisites  
Before running the project, ensure you have the following installed:  
- Python 3.x (preferably Python 3.11)  
- Nmap (for network reconnaissance)  
- pip (for Python package management)  

## Installation  
Clone this repository to your local machine:  
```
git clone https://github.com/rajkumar-vishe/rajkumar-vishe-Automated-Adversarial-Emulation-Framework.git  
cd Automated-Adversarial-Emulation-Framework  
```
 Install the required dependencies
```
pip install -r requirements.txt
```
(Optional) Install Nmap if not already installed on your system. You can follow the instructions from Nmap's official website.

## Usage
To run the entire red team exercise, execute the main.py script. This will:
- Perform network reconnaissance on the target IP range.
- Scan for open ports and attempt to exploit vulnerabilities.
- Run detection tests to simulate attack evasion strategies.
- Generate a comprehensive security report with the findings.
- DO NOT FORGET TO ADD/CHANGE TARGET MACHINE IP AND YOUR MACHINE IP ADDRESS
```
python main.py
```
Example Output:
- Reconnaissance: The script scans a given IP range and checks for open ports.
- Exploitation: The script attempts to exploit vulnerabilities like PHP CGI (port 80) and vsftpd (port 21) based on scan results.
- Detection Testing: The script simulates attack evasion techniques to test detection mechanisms.
- Security Report: A report summarizing scan results, exploitation success/failure, and detection effectiveness will be generated in the results/ directory.

## Modules
### 1. Reconnaissance
The reconnaissance module performs a network scan using Nmap to detect live hosts and open ports.
- File: modules/reconnaissance.py
- Key Function: scan_network() – Scans a given IP range for open ports.
### 2. Exploit Engine
This module attempts to exploit known vulnerabilities on open ports, such as PHP CGI vulnerability on port 80 or vsftpd vulnerability on port 21.
- File: modules/exploit_engine.py
- Key Functions:
  - exploit_php_cgi() – Exploits PHP CGI vulnerability on port 80.
  - exploit_vsftpd() – Exploits vsftpd vulnerability on port 21.
### 3. Detection Testing
This module simulates various evasion strategies, such as payload obfuscation and randomized delays, to test the effectiveness of detection systems (IDS/IPS) against red team tactics.
- File: modules/detection_testing.py
- Key Function: run_detection_tests() – Runs tests to check if attacks can be detected.
### 4. Report Generation
Generates a comprehensive security report based on the results of the reconnaissance, exploitation, and detection testing phases. This report is saved in the results/ directory.
- File: modules/report_generation.py
- Key Function: generate_report() – Creates a detailed report summarizing findings.

## Disclaimer  
This project is intended for educational and experimental purposes only. It is your responsibility to ensure that you have proper authorization to perform scans, exploitation, or testing on any target. Unauthorized use of this framework on real-world systems without explicit permission may violate laws and regulations.  

We strongly recommend using this project on virtual machines (VMs) or isolated environments specifically designed for security testing, such as:  
- Metasploitable  
- OWASP Juice Shop  
- DVWA (Damn Vulnerable Web Application)

By using this framework, you agree to take full responsibility for any actions taken with the code and any consequences that may arise.  

## License
This project is not licensed for redistribution or modification.
You are welcome to clone or download the repository for personal use only. For other purposes, please contact the author for explicit permission.
