#!/usr/bin/env python3
"""
Port Scanner Module

This module provides functionality for port scanning and service detection:
1. TCP port scanning
2. Service version detection
3. Banner grabbing
4. Common port identification
"""

import socket
import concurrent.futures
import time
import sys
import re
import subprocess
import platform
import json

class PortScanner:
    """Class for port scanning and service detection"""
    
    # Common ports and their services
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    def __init__(self, threads=10, timeout=5, use_nmap=False):
        """
        Initialize the port scanner
        
        Args:
            threads (int): Number of concurrent threads to use
            timeout (int): Timeout for connection attempts in seconds
            use_nmap (bool): Whether to use nmap for service detection
        """
        self.threads = threads
        self.timeout = timeout
        self.use_nmap = use_nmap
        self._check_nmap_availability()
    
    def _check_nmap_availability(self):
        """Check if nmap is available on the system"""
        if self.use_nmap:
            try:
                # Check if nmap is installed
                if platform.system() == "Windows":
                    result = subprocess.run(["where", "nmap"], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE)
                else:
                    result = subprocess.run(["which", "nmap"], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE)
                
                if result.returncode != 0:
                    print("Warning: nmap not found. Falling back to socket-based scanning.")
                    self.use_nmap = False
            except Exception as e:
                print(f"Error checking nmap availability: {str(e)}")
                self.use_nmap = False
    
    def scan(self, target, ports="21,22,25,53,80,110,143,443,445,3306,3389,8080,8443"):
        """
        Scan ports on a target host
        
        Args:
            target (str): Target hostname or IP address
            ports (str): Comma-separated list of ports or port ranges
        
        Returns:
            dict: Dictionary of open ports and their services
        """
        print(f"Scanning ports on {target}")
        
        # Parse ports string into a list of integers
        port_list = self._parse_ports(ports)
        
        if self.use_nmap:
            return self._scan_with_nmap(target, port_list)
        else:
            return self._scan_with_sockets(target, port_list)
    
    def _parse_ports(self, ports_str):
        """Parse a string of ports into a list of integers"""
        port_list = []
        
        # Split by comma
        for part in ports_str.split(','):
            # Check if it's a range (e.g., 80-100)
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                # Single port
                port_list.append(int(part))
        
        return port_list
    
    def _scan_with_sockets(self, target, port_list):
        """Scan ports using Python sockets"""
        open_ports = {}
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {target}")
            return open_ports
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip, port): port 
                for port in port_list
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = self._identify_service(port, banner)
                        open_ports[port] = {
                            "service": service,
                            "banner": banner
                        }
                        print(f"Port {port} is open: {service}")
                except Exception as e:
                    print(f"Error scanning port {port}: {str(e)}")
        
        return open_ports
    
    def _check_port(self, ip, port):
        """Check if a port is open and grab banner"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port is open, try to grab banner
                banner = self._grab_banner(sock)
                return True, banner
            return False, ""
        except Exception:
            return False, ""
        finally:
            sock.close()
    
    def _grab_banner(self, sock):
        """Attempt to grab a service banner"""
        try:
            # Send a generic request that might elicit a response
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""
    
    def _identify_service(self, port, banner):
        """Identify service based on port number and banner"""
        # Check common ports first
        if port in self.COMMON_PORTS:
            service = self.COMMON_PORTS[port]
            
            # Try to enhance with version info from banner
            if banner:
                # HTTP server
                if service in ["HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"]:
                    server_match = re.search(r'Server: ([^\r\n]+)', banner)
                    if server_match:
                        return f"{service} ({server_match.group(1)})"
                
                # SSH
                if service == "SSH" and "SSH" in banner:
                    return f"SSH ({banner.split()[0]})"
                
                # FTP
                if service == "FTP" and "FTP" in banner:
                    return f"FTP ({' '.join(banner.split()[:2])})"
            
            return service
        
        # Try to identify from banner
        if banner:
            if "SSH" in banner:
                return f"SSH ({banner.split()[0]})"
            if "FTP" in banner:
                return f"FTP ({' '.join(banner.split()[:2])})"
            if "HTTP" in banner:
                server_match = re.search(r'Server: ([^\r\n]+)', banner)
                if server_match:
                    return f"HTTP ({server_match.group(1)})"
            
            # Return first line of banner if we can't identify
            return banner.split('\n')[0][:30]
        
        # Default to "Unknown"
        return "Unknown"
    
    def _scan_with_nmap(self, target, port_list):
        """Scan ports using nmap"""
        open_ports = {}
        
        try:
            # Convert port list to nmap format
            ports_str = ",".join(map(str, port_list))
            
            # Run nmap command
            cmd = ["nmap", "-sV", "-p", ports_str, target, "-oX", "-"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                print(f"Error running nmap: {result.stderr}")
                return self._scan_with_sockets(target, port_list)
            
            # Parse XML output
            # This is a simplified parser, a real implementation would use xml.etree.ElementTree
            for line in result.stdout.split('\n'):
                port_match = re.search(r'<port protocol="tcp" portid="(\d+)"><state state="open"', line)
                if port_match:
                    port = int(port_match.group(1))
                    
                    # Try to get service info
                    service_match = re.search(r'<service name="([^"]+)" product="([^"]*)" version="([^"]*)"', line)
                    if service_match:
                        service_name = service_match.group(1)
                        product = service_match.group(2)
                        version = service_match.group(3)
                        
                        service_info = service_name
                        if product:
                            service_info += f" ({product}"
                            if version:
                                service_info += f" {version}"
                            service_info += ")"
                        
                        open_ports[port] = {
                            "service": service_info,
                            "banner": ""
                        }
                        print(f"Port {port} is open: {service_info}")
        except Exception as e:
            print(f"Error with nmap scan: {str(e)}")
            # Fall back to socket scanning
            return self._scan_with_sockets(target, port_list)
        
        return open_ports

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Port scanner tool')
    parser.add_argument('-t', '--target', required=True, help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', default="21,22,25,53,80,110,143,443,445,3306,3389,8080,8443", 
                      help='Comma-separated list of ports or port ranges')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout for connection attempts in seconds (default: 5)')
    parser.add_argument('--nmap', action='store_true', help='Use nmap for service detection')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Run the port scanner
    scanner = PortScanner(threads=args.threads, timeout=args.timeout, use_nmap=args.nmap)
    results = scanner.scan(args.target, args.ports)
    
    # Print summary
    print(f"\nScan complete. Found {len(results)} open ports on {args.target}")
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {args.output}")