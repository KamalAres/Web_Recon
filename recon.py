import requests
import socket
import os
from urllib.parse import urlparse
from crt import get_subdomains

def resolve_hostname_to_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"Hostname: {hostname}\nResolved IP Address: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"Error: Unable to resolve {hostname} to an IP address.")
        return None

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": "HSTS (HTTP Strict Transport Security) prevents man-in-the-middle attacks.",
            "Content-Security-Policy": "CSP helps prevent XSS attacks by defining allowed content sources.",
            "X-Frame-Options": "Protects against clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME-type sniffing.",
            "Referrer-Policy": "Controls how much referrer information is shared.",
            "Permissions-Policy": "Restricts browser features like camera, microphone, etc.",
            "X-XSS-Protection": "Legacy header to prevent some forms of XSS attacks."
        }

        print(f"Checking security headers for: {url}\n")
        for header, description in security_headers.items():
            if header in headers:
                print(f"✅ {header}: Present")
            else:
                print(f"❌ {header}: Missing - {description}")
    
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def check_cors_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        cors_headers = ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"]
        
        print(f"\nChecking CORS headers for: {url}\n")
        for header in cors_headers:
            if header in headers:
                print(f"✅ {header}: {headers[header]}")
            else:
                print(f"❌ {header}: Missing")
    
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def strip_url(url):
    parsed_url = urlparse(url)
    return parsed_url.hostname if parsed_url.hostname else url

def enumerate_subdomains(hostname):
    print("\nSelect subdomain enumeration method:")
    print("1. Certificate Transparency Logs (crt.sh)")
    print("2. Wordlist-based enumeration")
    
    choice = input("\nEnter your choice (1 or 2): ")
    
    if choice == '2':
        custom_wordlist = input("\nEnter path to custom wordlist (leave empty for default): ")
        if custom_wordlist and not os.path.exists(custom_wordlist):
            print(f"Warning: Wordlist not found at {custom_wordlist}, using default wordlist")
            custom_wordlist = None
        
        print("\nEnumerating subdomains using wordlist...")
        subdomains = get_subdomains(hostname, method='wordlist', wordlist_path=custom_wordlist)
    else:
        print("\nEnumerating subdomains using certificate transparency logs...")
        subdomains = get_subdomains(hostname, method='crt')
    
    print("\nSubdomains found:")
    print(f"Number of subdomains found: {len(subdomains)}")
    for subdomain in subdomains:
        print(subdomain)
    
    return subdomains

if __name__ == "__main__":
    target_url = input("Enter website URL (including http/https): ")
    check_security_headers(target_url)
    check_cors_headers(target_url)
    hostname = strip_url(target_url)
    ip_address = resolve_hostname_to_ip(hostname)
    
    if ip_address:
        perform_subdomain_enum = input("\nWould you like to perform subdomain enumeration? (y/n): ")
        if perform_subdomain_enum.lower() == 'y':
            enumerate_subdomains(hostname)