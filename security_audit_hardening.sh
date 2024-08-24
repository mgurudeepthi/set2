#!/bin/bash

  # Function to list all users and groups

   audit_users_groups() {
   
        echo "User and Group Audit:"
        echo "====================="
	awk -F':' '{ print $1 }' /etc/passwd
	echo "Groups:"
	awk -F':' '{ print $1 }' /etc/group
	echo ""


	# Check for users with UID 0 (root privileges)
	echo "Users with UID 0 (root privileges):"
	awk -F':' '$3 == 0 { print $1 }' /etc/passwd
	echo ""


	# Identify users without passwords or with weak passwords
	echo "Users without passwords or with weak passwords:"
	awk -F':' '($2 == "" || $2 == "*" || $2 == "!") { print $1 }' /etc/shadow
	echo ""
   }


   # Function to scan for files and directories with world-writable permissions

   audit_file_permissions() {

       echo "File and Directory Permissions Audit:"
       echo "===================================="
       echo "World-writable files and directories:"
       find / -type f -perm -o+w -ls
       find / -type d -perm -o+w -ls
       echo ""


       # Check for .ssh directories and ensure they have secure permissions

       echo "Checking .ssh directory permissions:"
       find /home -type d -name ".ssh" -exec ls -ld {} \;
       find /root -type d -name ".ssh" -exec ls -ld {} \;
       echo ""


       # Report any files with SUID or SGID bits set

       echo "Files with SUID or SGID bits set:"
       find / -perm /6000 -type f -exec ls -ld {} \;
       echo ""
   }

   # Function to list all running services and check for unnecessary or unauthorized services

   audit_services() {
       
       echo "Service Audit:"
       echo "============="
       echo "Running services:"
       systemctl list-units --type=service --state=running
       echo ""

       # Check for critical services
       echo "Checking critical services (e.g., sshd, iptables):"
       systemctl status sshd iptables
       echo ""

       # Check for services listening on non-standard or insecure ports
       echo "Services listening on non-standard or insecure ports:"
       netstat -tulnp
       echo ""
  }

  # Function to verify firewall status and open ports

  audit_firewall() {
   
       echo "Firewall and Network Security:"
        echo "============================="
	echo "Checking firewall status:"
	ufw status || iptables -L
	echo ""
     # Report any open ports and associated services
       
       echo "Open ports and associated services:"
       netstat -tuln
       echo ""

     # Check for IP forwarding or other insecure network configurations
        echo "Checking IP forwarding status:"
	sysctl net.ipv4.ip_forward
	sysctl net.ipv6.conf.all.forwarding
	echo ""
   }

  # Function to identify public vs. private IPs

  audit_ip_configuration() {
    
    echo "IP and Network Configuration Checks:"
    echo "==================================="
    ip -4 addr show
    ip -6 addr show


    echo "Public vs. Private IP Checks:"
    for ip in $(hostname -I); do
    if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.16\. ]] || [[ $ip =~ ^192\.168\. ]]; then
          echo "Private IP: $ip"
     else
         echo "Public IP: $ip"
       fi
      done
        echo ""
  }

  # Function to check for and report available security updates

  audit_security_updates() {
      
      echo "Security Updates and Patching:"
      echo "============================="
      echo "Checking for security updates:"
      apt-get update && apt-get -s upgrade | grep "^Inst" | grep -i security
      echo ""

      # Ensure regular security updates are configured
      echo "Ensuring automatic security updates:"
      dpkg-reconfigure --priority=low unattended-upgrades
      echo ""

  }

  # Function to check recent suspicious log entries

  audit_log_monitoring() {
     
     echo "Log Monitoring:"
     echo "==============="
     echo "Checking for suspicious SSH login attempts:"
     grep "Failed password" /var/log/auth.log | tail -n 10
      echo ""

  }

  # Function to implement SSH key-based authentication and other hardening steps

  harden_server() {
      
      echo "Server Hardening:"
      echo "================"
      echo "Implementing SSH key-based authentication:"
      sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
      systemctl reload sshd
      echo "SSH key-based authentication enabled, root password login disabled."
      

      echo "Disabling IPv6 if not required:"
      echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
      echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
      sysctl -p
      echo "IPv6 disabled."

      echo "Setting GRUB bootloader password:"
      grub-mkpasswd-pbkdf2  # Follow prompts to set a password
      echo "Set GRUB bootloader password."

      echo "Configuring iptables firewall rules:"
      iptables -P INPUT DROP
      iptables -P FORWARD DROP
      iptables -P OUTPUT ACCEPT
      iptables -A INPUT -i lo -j ACCEPT
      iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables-save > /etc/iptables/rules.v4
      echo "Iptables rules configured."

      echo "Configuring unattended-upgrades for automatic updates:"
      apt-get install unattended-upgrades
      dpkg-reconfigure --priority=low unattended-upgrades
      echo "Automatic updates configured."
  }


  # Function to handle custom security checks
    
    custom_security_checks() {
       
       echo "Custom Security Checks:"
       echo "======================="
       # Example custom check: Check for a specific config file
       if [ -f /etc/specialconfig.conf ]; then
          echo "Custom config file found: /etc/specialconfig.conf"
       else
          echo "Custom config file not found."
       fi
       echo ""
  }
  
  # Function to generate a summary report
    
    generate_report() {
     
        echo "Security Audit and Hardening Report"
	echo "==================================="
	audit_users_groups
	audit_file_permissions
	audit_services
	audit_firewall
	audit_ip_configuration
	audit_security_updates
	audit_log_monitoring
	harden_server
	custom_security_checks
	echo "Audit and Hardening Completed."
  }

  # Run the full audit and hardening process
  generate_report

