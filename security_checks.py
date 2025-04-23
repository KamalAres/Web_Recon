#!/usr/bin/env python3
"""
Security Checks Module

This module provides functionality for security checks:
1. HTTP security headers analysis
2. SSL/TLS configuration checks
3. CORS configuration checks
4. Common security misconfigurations
5. Information disclosure checks
"""

import requests
import socket
import ssl
import json
import re
import urllib3
from urllib.parse import urlparse

class SecurityChecker:
    """Class for security checks"""
    
    def __init__(self):
        """Initialize the security checker"""
        # Disable SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Define security headers to check
        self.security_headers = {
            "Strict-Transport-Security": {
                "description": "HTTP Strict Transport Security (HSTS) prevents man-in-the-middle attacks",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
            },
            "Content-Security-Policy": {
                "description": "Content Security Policy (CSP) helps prevent XSS attacks",
                "recommendation": "Implement a Content Security Policy"
            },
            "X-Frame-Options": {
                "description": "X-Frame-Options prevents clickjacking attacks",
                "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header"
            },
            "X-Content-Type-Options": {
                "description": "X-Content-Type-Options prevents MIME type sniffing",
                "recommendation": "Add 'X-Content-Type-Options: nosniff' header"
            },
            "Referrer-Policy": {
                "description": "Referrer-Policy controls how much referrer information is shared",
                "recommendation": "Add 'Referrer-Policy: no-referrer' or 'Referrer-Policy: same-origin' header"
            },
            "Permissions-Policy": {
                "description": "Permissions-Policy restricts browser features",
                "recommendation": "Implement a Permissions-Policy to restrict browser features"
            },
            "X-XSS-Protection": {
                "description": "X-XSS-Protection helps prevent XSS attacks in older browsers",
                "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header"
            }
        }
        
        # Define CORS headers to check
        self.cors_headers = [
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Credentials"
        ]
    
    def check(self, domain):
        """
        Perform security checks on a domain
        
        Args:
            domain (str): Domain to check
        
        Returns:
            list: List of security issues found
        """
        print(f"Performing security checks on {domain}")
        
        issues = []
        
        # Ensure domain has a scheme
        if not domain.startswith(('http://', 'https://')):
            http_url = f"http://{domain}"
            https_url = f"https://{domain}"
        else:
            parsed = urlparse(domain)
            http_url = f"http://{parsed.netloc}"
            https_url = f"https://{parsed.netloc}"
            domain = parsed.netloc
        
        # Check HTTP security headers
        header_issues = self._check_security_headers(http_url, https_url)
        issues.extend(header_issues)
        
        # Check CORS configuration
        cors_issues = self._check_cors_configuration(http_url, https_url)
        issues.extend(cors_issues)
        
        # Check SSL/TLS configuration
        ssl_issues = self._check_ssl_configuration(domain)
        issues.extend(ssl_issues)
        
        # Check for information disclosure
        info_issues = self._check_information_disclosure(http_url, https_url)
        issues.extend(info_issues)
        
        # Print summary
        print(f"Found {len(issues)} security issues for {domain}")
        for issue in issues:
            print(f"  - {issue['title']}: {issue['description']}")
        
        return issues
    
    def _check_security_headers(self, http_url, https_url):
        """Check for missing or misconfigured security headers"""
        issues = []
        
        try:
            # Try HTTPS first
            try:
                response = requests.get(https_url, timeout=10, verify=False)
                url_used = https_url
            except requests.exceptions.RequestException:
                # Fall back to HTTP
                response = requests.get(http_url, timeout=10)
                url_used = http_url
            
            # Check for missing security headers
            for header, info in self.security_headers.items():
                if header not in response.headers:
                    issues.append({
                        "title": f"Missing {header} Header",
                        "description": info["description"],
                        "severity": "Medium",
                        "recommendation": info["recommendation"],
                        "url": url_used
                    })
            
            # Check for misconfigured headers
            if "X-Frame-Options" in response.headers:
                value = response.headers["X-Frame-Options"].upper()
                if value not in ["DENY", "SAMEORIGIN"]:
                    issues.append({
                        "title": "Misconfigured X-Frame-Options Header",
                        "description": "X-Frame-Options should be set to DENY or SAMEORIGIN",
                        "severity": "Medium",
                        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN",
                        "url": url_used
                    })
            
            if "Strict-Transport-Security" in response.headers:
                value = response.headers["Strict-Transport-Security"].lower()
                if "max-age=" not in value or int(re.search(r'max-age=(\d+)', value).group(1)) < 31536000:
                    issues.append({
                        "title": "Weak HSTS Configuration",
                        "description": "HSTS max-age should be at least 1 year (31536000 seconds)",
                        "severity": "Medium",
                        "recommendation": "Set Strict-Transport-Security with max-age of at least 31536000",
                        "url": url_used
                    })
        
        except requests.exceptions.RequestException as e:
            print(f"Error checking security headers: {str(e)}")
        
        return issues
    
    def _check_cors_configuration(self, http_url, https_url):
        """Check for misconfigured CORS headers"""
        issues = []
        
        try:
            # Try HTTPS first
            try:
                response = requests.get(
                    https_url, 
                    headers={"Origin": "https://evil.com"}, 
                    timeout=10, 
                    verify=False
                )
                url_used = https_url
            except requests.exceptions.RequestException:
                # Fall back to HTTP
                response = requests.get(
                    http_url, 
                    headers={"Origin": "http://evil.com"}, 
                    timeout=10
                )
                url_used = http_url
            
            # Check for overly permissive CORS
            if "Access-Control-Allow-Origin" in response.headers:
                value = response.headers["Access-Control-Allow-Origin"]
                if value == "*" or value == "https://evil.com" or value == "http://evil.com":
                    issues.append({
                        "title": "Overly Permissive CORS Configuration",
                        "description": "Access-Control-Allow-Origin header allows requests from any origin",
                        "severity": "High",
                        "recommendation": "Restrict CORS to specific trusted origins",
                        "url": url_used
                    })
            
            # Check for credentials with permissive origin
            if ("Access-Control-Allow-Credentials" in response.headers and 
                response.headers["Access-Control-Allow-Credentials"].lower() == "true" and
                "Access-Control-Allow-Origin" in response.headers and
                response.headers["Access-Control-Allow-Origin"] == "*"):
                issues.append({
                    "title": "Insecure CORS Configuration with Credentials",
                    "description": "Access-Control-Allow-Credentials is true with wildcard origin",
                    "severity": "High",
                    "recommendation": "Do not use wildcard origin with Access-Control-Allow-Credentials",
                    "url": url_used
                })
        
        except requests.exceptions.RequestException as e:
            print(f"Error checking CORS configuration: {str(e)}")
        
        return issues
    
    def _check_ssl_configuration(self, domain):
        """Check for SSL/TLS configuration issues"""
        issues = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Try to establish SSL connection
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    import datetime
                    expires = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    remaining = expires - datetime.datetime.now()
                    
                    if remaining.days < 30:
                        issues.append({
                            "title": "SSL Certificate Expiring Soon",
                            "description": f"SSL certificate expires in {remaining.days} days",
                            "severity": "Medium",
                            "recommendation": "Renew the SSL certificate",
                            "url": f"https://{domain}"
                        })
                    
                    # Check for weak cipher suites (simplified)
                    cipher = ssock.cipher()
                    if cipher[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5']:
                        issues.append({
                            "title": "Weak SSL/TLS Cipher Suite",
                            "description": f"Weak cipher suite in use: {cipher[0]}",
                            "severity": "High",
                            "recommendation": "Configure server to use strong cipher suites",
                            "url": f"https://{domain}"
                        })
        
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            # HTTPS not available
            issues.append({
                "title": "HTTPS Not Available",
                "description": "The server does not support HTTPS",
                "severity": "High",
                "recommendation": "Implement HTTPS with a valid SSL certificate",
                "url": f"http://{domain}"
            })
        except ssl.SSLError as e:
            issues.append({
                "title": "SSL/TLS Error",
                "description": f"SSL/TLS error: {str(e)}",
                "severity": "High",
                "recommendation": "Fix SSL/TLS configuration",
                "url": f"https://{domain}"
            })
        except Exception as e:
            print(f"Error checking SSL configuration: {str(e)}")
        
        return issues
    
    def _check_information_disclosure(self, http_url, https_url):
        """Check for information disclosure issues"""
        issues = []
        
        # Common paths that might disclose sensitive information
        sensitive_paths = [
            "/.git/",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/.htaccess",
            "/robots.txt",
            "/.well-known/security.txt"
        ]
        
        for path in sensitive_paths:
            try:
                # Try HTTPS first
                try:
                    url = https_url + path
                    response = requests.get(url, timeout=5, verify=False)
                except requests.exceptions.RequestException:
                    # Fall back to HTTP
                    url = http_url + path
                    response = requests.get(url, timeout=5)
                
                # Check if the response might contain sensitive information
                if response.status_code == 200:
                    # Check content length to avoid false positives
                    if len(response.content) > 0:
                        issues.append({
                            "title": "Potential Information Disclosure",
                            "description": f"The path {path} might expose sensitive information",
                            "severity": "Medium",
                            "recommendation": f"Restrict access to {path}",
                            "url": url
                        })
            
            except requests.exceptions.RequestException:
                # Path not accessible, which is good
                pass
        
        return issues

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Security checks tool')
    parser.add_argument('-d', '--domain', required=True, help='Domain to check')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Run the security checker
    checker = SecurityChecker()
    issues = checker.check(args.domain)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(issues, f, indent=4)
        print(f"Results saved to {args.output}")