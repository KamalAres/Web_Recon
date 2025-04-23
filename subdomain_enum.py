#!/usr/bin/env python3
"""
Subdomain Enumeration Module

This module provides functionality for subdomain enumeration using various techniques:
1. Wordlist-based brute force
2. Certificate Transparency logs
3. DNS records
4. Third-party services (VirusTotal, ThreatCrowd)
"""

import socket
import os
import sys
import concurrent.futures
import requests
import time
import json
from urllib.parse import urlparse

class SubdomainEnumerator:
    """Class for subdomain enumeration using multiple techniques"""
    
    def __init__(self, domain, wordlist_path=None, threads=10, 
                 use_virustotal=False, use_threatcrowd=True, virustotal_api_key=None):
        """
        Initialize the subdomain enumerator
        
        Args:
            domain (str): The target domain (e.g., example.com)
            wordlist_path (str): Path to the wordlist file for brute force
            threads (int): Number of concurrent threads to use
            use_virustotal (bool): Whether to use VirusTotal API
            use_threatcrowd (bool): Whether to use ThreatCrowd API
            virustotal_api_key (str): API key for VirusTotal
        """
        self.domain = domain
        self.wordlist_path = wordlist_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'default_subdomains.txt'
        )
        self.threads = threads
        self.use_virustotal = use_virustotal
        self.use_threatcrowd = use_threatcrowd
        self.virustotal_api_key = virustotal_api_key
        self.subdomains = set()
        
    def enumerate(self):
        """
        Perform subdomain enumeration using all configured methods
        
        Returns:
            list: List of discovered subdomains
        """
        print(f"Starting subdomain enumeration for {self.domain}")
        
        # Wordlist-based enumeration
        if os.path.exists(self.wordlist_path):
            self._enumerate_from_wordlist()
        else:
            print(f"Warning: Wordlist not found at {self.wordlist_path}")
        
        # Certificate transparency logs
        self._enumerate_from_crt()
        
        # VirusTotal
        if self.use_virustotal and self.virustotal_api_key:
            self._enumerate_from_virustotal()
        
        # ThreatCrowd
        if self.use_threatcrowd:
            self._enumerate_from_threatcrowd()
        
        print(f"Found {len(self.subdomains)} subdomains for {self.domain}")
        return list(self.subdomains)
    
    def _is_subdomain_resolvable(self, subdomain):
        """Check if a subdomain resolves to an IP address"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
    
    def _enumerate_from_wordlist(self):
        """Enumerate subdomains using a wordlist"""
        print(f"Enumerating subdomains for {self.domain} using wordlist: {self.wordlist_path}")
        
        try:
            with open(self.wordlist_path, 'r') as f:
                prefixes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading wordlist: {str(e)}")
            return
        
        potential_subdomains = [f"{prefix}.{self.domain}" for prefix in prefixes]
        
        # Use ThreadPoolExecutor for parallel resolution
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._is_subdomain_resolvable, subdomain): subdomain 
                for subdomain in potential_subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        self.subdomains.add(subdomain)
                        print(f"Found subdomain: {subdomain}")
                except Exception as e:
                    print(f"Error checking {subdomain}: {str(e)}")
    
    def _enumerate_from_crt(self):
        """Enumerate subdomains using certificate transparency logs"""
        print(f"Enumerating subdomains for {self.domain} using certificate transparency logs")
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines and handle wildcards
                    for subdomain in name_value.split('\\n'):
                        subdomain = subdomain.strip()
                        # Skip wildcards
                        if subdomain.startswith('*'):
                            continue
                        # Ensure it's a subdomain of the target domain
                        if subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
                            self.subdomains.add(subdomain)
                            print(f"Found subdomain: {subdomain}")
        except Exception as e:
            print(f"Error enumerating from certificate transparency logs: {str(e)}")
    
    def _enumerate_from_virustotal(self):
        """Enumerate subdomains using VirusTotal API"""
        print(f"Enumerating subdomains for {self.domain} using VirusTotal API")
        
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
                        self.subdomains.add(subdomain)
                        print(f"Found subdomain: {subdomain}")
        except Exception as e:
            print(f"Error enumerating from VirusTotal: {str(e)}")
    
    def _enumerate_from_threatcrowd(self):
        """Enumerate subdomains using ThreatCrowd API"""
        print(f"Enumerating subdomains for {self.domain} using ThreatCrowd API")
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    if subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
                        self.subdomains.add(subdomain)
                        print(f"Found subdomain: {subdomain}")
            
            # ThreatCrowd has rate limiting, so sleep to avoid issues
            time.sleep(10)
        except Exception as e:
            print(f"Error enumerating from ThreatCrowd: {str(e)}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Subdomain enumeration tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--virustotal', help='VirusTotal API key')
    
    args = parser.parse_args()
    
    # Run the subdomain enumeration
    enumerator = SubdomainEnumerator(
        args.domain, 
        wordlist_path=args.wordlist,
        threads=args.threads,
        use_virustotal=bool(args.virustotal),
        virustotal_api_key=args.virustotal
    )
    
    subdomains = enumerator.enumerate()
    print(f"\nTotal subdomains found: {len(subdomains)}")