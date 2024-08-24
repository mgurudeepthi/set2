# Security Audit and Hardening Script

## Overview

This script automates the security audit and hardening process for Linux servers. It performs a comprehensive check of various security aspects, including user and group audits, file and directory permissions, service audits, firewall and network security, IP configuration, security updates, log monitoring, and server hardening. The script is modular and designed to be reusable across different servers.

## Features

- User and Group Audits
- File and Directory Permissions Checks
- Service Audits
- Firewall and Network Security Verification
- IP and Network Configuration Checks
- Security Updates and Patching
- Log Monitoring
- Server Hardening Steps
- Custom Security Checks
- Reporting and Alerting

## Prerequisites

- A Linux server with Bash shell
- Sudo or root access
- Basic tools like `netstat`, `awk`, `find`, `systemctl`, `ufw`, `iptables`, `grep`, and `apt-get`

## Usage

1. **Clone the Repository** (if hosted on GitHub):

    ```bash
        git clone https://github.com/mgurudeepthi/set2.git
	    cd your-repo-name
	        ```

		2. **Make the Script Executable**:

		    ```bash
		        chmod +x security_audit_hardening.sh
			    ```

			    3. **Run the Script**:

			        ```bash
				    sudo ./security_audit_hardening.sh
				        ```

					   Note: Use `sudo` to ensure the script has the necessary permissions to perform all tasks.

					   ## Script Details
# Security Audit and Hardening Script

## Overview

This script automates the security audit and hardening process for Linux servers. It performs a comprehensive check of various security aspects, including user and group audits, file and directory permissions, service audits, firewall and network security, IP configuration, security updates, log monitoring, and server hardening. The script is modular and designed to be reusable across different servers.

## Features

- User and Group Audits
- File and Directory Permissions Checks
- Service Audits
- Firewall and Network Security Verification
- IP and Network Configuration Checks
- Security Updates and Patching
- Log Monitoring
- Server Hardening Steps
- Custom Security Checks
- Reporting and Alerting


## Prerequisites

- A Linux server with Bash shell
- Sudo or root access
- Basic tools like `netstat`, `awk`, `find`, `systemctl`, `ufw`, `iptables`, `grep`, and `apt-get`


## Usage
  
  1. **Clone the Repository** (if hosted on GitHub):
     
     ```bash
         git clone https://github.com/mgurudeepthi/set2.git
	     cd your-repo-name
	         ```
  2. **Make the Script Executable**:
    
    ```bash
        chmod +x security_audit_hardening.sh
	    ```
  3. **Run the Script**:

     ```bash
         sudo ./security_audit_hardening.sh
	     ```
 
 Note: Use `sudo` to ensure the script has the necessary permissions to perform all tasks.


 ## Script Details

 ### 1. User and Group Audits
 - Lists all users and groups
 - Checks for users with UID 0
 - Identifies users without passwords or with weak passwords

 ### 2. File and Directory Permissions
 - Scans for world-writable files and directories
 - Checks permissions of `.ssh` directories
 - Reports files with SUID or SGID bits set

 ### 3. Service Audits
 - Lists all running services
 - Checks for critical services and non-standard ports


 ### 4. Firewall and Network Security
 - Verifies firewall status and configuration
 - Reports open ports and associated services
 - Checks IP forwarding and network configurations

 ### 5. IP and Network Configuration Checks
 - Identifies public vs. private IP addresses
 - Provides a summary of all IP addresses


 ### 6. Security Updates and Patching
 - Checks for available security updates
 - Ensures automatic updates are configured

 ### 7. Log Monitoring
 - Checks for suspicious log entries related to SSH

 ### 8. Server Hardening Steps
 - Implements SSH key-based authentication
 - Disables IPv6 if not required
 - Sets GRUB bootloader password
 - Configures iptables firewall rules
 - Configures automatic security updates

 ### 9. Custom Security Checks
 - Includes placeholder for custom checks


 ### 10. Reporting and Alerting
 - Generates a summary report of the audit and hardening process


 ## Contact

 For questions or issues, please open an issue on the [GitHub repository]
(https://github.com/mgurudeepthi/set2.git)
