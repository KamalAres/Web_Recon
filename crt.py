#!/usr/bin/env python3
"""
Certificate Transparency Log Module

This module provides functionality for retrieving subdomains from certificate transparency logs
and performing wordlist-based subdomain enumeration.
"""

import requests
import socket
import os
import concurrent.futures
import time
import json
from urllib.parse import urlparse

def get_subdomains(domain, method='crt', wordlist_path=None):
    """
    Get subdomains for a domain using specified method
    
    Args:
        domain (str): The target domain (e.g., example.com)
        method (str): Method to use ('crt' or 'wordlist')
        wordlist_path (str): Path to wordlist file for wordlist method
    
    Returns:
        list: List of discovered subdomains
    """
    print(f"Getting subdomains for {domain} using {method} method")
    
    if method == 'crt':
        return get_subdomains_from_crt(domain)
    elif method == 'wordlist':
        return get_subdomains_from_wordlist(domain, wordlist_path)
    else:
        print(f"Error: Unknown method '{method}'. Using crt method instead.")
        return get_subdomains_from_crt(domain)

def get_subdomains_from_crt(domain):
    """
    Get subdomains from certificate transparency logs
    
    Args:
        domain (str): The target domain (e.g., example.com)
    
    Returns:
        list: List of discovered subdomains
    """
    print(f"Searching certificate transparency logs for {domain}")
    
    subdomains = set()
    
    try:
        # Query crt.sh for certificates
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                # Process each certificate
                for cert in data:
                    # Get the name value which may contain multiple subdomains
                    name_value = cert.get('name_value', '')
                    
                    # Split by newlines and handle wildcards
                    for subdomain in name_value.split('\\n'):
                        subdomain = subdomain.strip()
                        
                        # Skip empty subdomains
                        if not subdomain:
                            continue
                        
                        # Handle wildcards
                        if subdomain.startswith('*'):
                            continue
                        
                        # Ensure it's a subdomain of the target domain
                        if subdomain.endswith(f".{domain}") and subdomain != domain:
                            # Check if the subdomain resolves
                            try:
                                socket.gethostbyname(subdomain)
                                subdomains.add(subdomain)
                                print(f"Found subdomain: {subdomain}")
                            except socket.gaierror:
                                # Subdomain doesn't resolve, skip it
                                pass
                        elif subdomain == domain:
                            # Add the main domain
                            subdomains.add(subdomain)
            except json.JSONDecodeError:
                print("Error: Invalid JSON response from crt.sh")
        else:
            print(f"Error: HTTP {response.status_code} response from crt.sh")
    
    except requests.exceptions.RequestException as e:
        print(f"Error querying crt.sh: {str(e)}")
    
    print(f"Found {len(subdomains)} subdomains from certificate transparency logs")
    return list(subdomains)

def get_subdomains_from_wordlist(domain, wordlist_path=None):
    """
    Get subdomains using wordlist-based enumeration
    
    Args:
        domain (str): The target domain (e.g., example.com)
        wordlist_path (str): Path to wordlist file
    
    Returns:
        list: List of discovered subdomains
    """
    # Use default wordlist if none provided
    if not wordlist_path or not os.path.exists(wordlist_path):
        wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'default_subdomains.txt')
        print(f"Using default wordlist: {wordlist_path}")
    
    print(f"Performing wordlist-based enumeration for {domain} using {wordlist_path}")
    
    subdomains = set()
    
    try:
        # Read wordlist
        with open(wordlist_path, 'r') as f:
            prefixes = [line.strip() for line in f if line.strip()]
        
        print(f"Loaded {len(prefixes)} prefixes from wordlist")
        
        # Generate potential subdomains
        potential_subdomains = [f"{prefix}.{domain}" for prefix in prefixes]
        
        # Check subdomains in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(is_subdomain_resolvable, subdomain): subdomain 
                for subdomain in potential_subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        subdomains.add(subdomain)
                        print(f"Found subdomain: {subdomain}")
                except Exception as e:
                    print(f"Error checking {subdomain}: {str(e)}")
    
    except Exception as e:
        print(f"Error during wordlist enumeration: {str(e)}")
    
    print(f"Found {len(subdomains)} subdomains from wordlist")
    return list(subdomains)

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

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Subdomain enumeration tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-m', '--method', choices=['crt', 'wordlist'], default='crt', 
                      help='Method to use (crt or wordlist)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file (for wordlist method)')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Get subdomains
    subdomains = get_subdomains(args.domain, args.method, args.wordlist)
    
    # Print results
    print(f"\nFound {len(subdomains)} subdomains for {args.domain}:")
    for subdomain in subdomains:
        print(subdomain)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        print(f"\nResults saved to {args.output}")