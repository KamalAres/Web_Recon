import requests
import socket
from urllib.parse import urlparse

def resolve_hostname_to_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"Hostname: {hostname}\nResolved IP Address: {ip_address}")
    except socket.gaierror:
        print(f"Error: Unable to resolve {hostname} to an IP address.")

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

if __name__ == "__main__":
    target_url = input("Enter website URL (including http/https): ")
    check_security_headers(target_url)
    check_cors_headers(target_url)
    hostname = strip_url(target_url)
    resolve_hostname_to_ip(hostname)