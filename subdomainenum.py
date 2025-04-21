#!/usr/bin/env python3
"""
SubdomainEnum - A Python CLI tool for subdomain enumeration

This tool performs subdomain enumeration similar to Gobuster by:
1. Accepting a target domain and wordlist path as arguments
2. Reading each line from the wordlist and appending it as a subdomain
3. Checking if the subdomain resolves using socket.gethostbyname()
4. Printing out only valid/resolvable subdomains
5. Supporting concurrency using concurrent.futures
"""

import argparse
import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_subdomain_resolvable(subdomain):
    """
    Check if a subdomain resolves to an IP address
    
    Args:
        subdomain (str): The subdomain to check
        
    Returns:
        bool: True if the subdomain resolves, False otherwise
    """
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False

def enumerate_subdomains(domain, wordlist_path, threads=10, verbose=False):
    """
    Enumerate subdomains by trying common subdomain names from a wordlist
    
    Args:
        domain (str): The target domain (e.g., example.com)
        wordlist_path (str): Path to the wordlist file
        threads (int): Number of concurrent threads to use
        verbose (bool): Whether to show verbose output
        
    Returns:
        list: List of valid subdomains
    """
    # Check if wordlist exists
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist not found at {wordlist_path}")
        sys.exit(1)
    
    try:
        with open(wordlist_path, 'r') as f:
            prefixes = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error: Failed to read wordlist - {str(e)}")
        sys.exit(1)
    
    valid_subdomains = []
    potential_subdomains = [f"{prefix}.{domain}" for prefix in prefixes]
    
    if verbose:
        print(f"Testing {len(potential_subdomains)} potential subdomains...")
    
    # Use ThreadPoolExecutor for parallel resolution
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {executor.submit(is_subdomain_resolvable, subdomain): subdomain for subdomain in potential_subdomains}
        
        # Process results as they complete
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                if future.result():
                    valid_subdomains.append(subdomain)
                    print(subdomain)
            except Exception as e:
                if verbose:
                    print(f"Error checking {subdomain}: {str(e)}")
    
    return valid_subdomains

def main():
    """Main function to parse arguments and run the subdomain enumeration"""
    parser = argparse.ArgumentParser(description='Subdomain enumeration tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Run the subdomain enumeration
    enumerate_subdomains(args.domain, args.wordlist, args.threads, args.verbose)

if __name__ == "__main__":
    main()