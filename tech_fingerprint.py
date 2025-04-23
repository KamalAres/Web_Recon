#!/usr/bin/env python3
"""
Technology Fingerprinting Module

This module provides functionality for identifying web technologies:
1. Web server identification
2. CMS detection
3. JavaScript frameworks detection
4. Web application frameworks detection
5. Analytics and tracking tools detection
"""

import requests
import re
import json
import os
import sys
import importlib.util
from urllib.parse import urlparse

class TechFingerprinter:
    """Class for fingerprinting web technologies"""
    
    def __init__(self, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"):
        """
        Initialize the technology fingerprinter
        
        Args:
            user_agent (str): User agent string to use for requests
        """
        self.user_agent = user_agent
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Load technology signatures
        self.signatures = self._load_signatures()
        
        # Check for optional dependencies
        self.has_builtwith = self._check_module("builtwith")
        self.has_webtech = self._check_module("webtech")
    
    def _check_module(self, module_name):
        """Check if a Python module is available"""
        return importlib.util.find_spec(module_name) is not None
    
    def _load_signatures(self):
        """Load technology signatures from built-in data"""
        # This is a simplified version with some common signatures
        # A real implementation would load from a comprehensive database
        return {
            "servers": {
                "Apache": {
                    "headers": ["Server"],
                    "regex": r"Apache(?:/([0-9.]+))?"
                },
                "Nginx": {
                    "headers": ["Server"],
                    "regex": r"nginx(?:/([0-9.]+))?"
                },
                "IIS": {
                    "headers": ["Server"],
                    "regex": r"Microsoft-IIS(?:/([0-9.]+))?"
                },
                "Cloudflare": {
                    "headers": ["Server", "CF-RAY"],
                    "regex": r"cloudflare"
                }
            },
            "cms": {
                "WordPress": {
                    "html": [
                        r"wp-content",
                        r"wp-includes",
                        r"<meta name=\"generator\" content=\"WordPress ([0-9.]+)\">"
                    ]
                },
                "Drupal": {
                    "html": [
                        r"Drupal.settings",
                        r"drupal.org",
                        r"<meta name=\"Generator\" content=\"Drupal ([0-9.]+)\">"
                    ]
                },
                "Joomla": {
                    "html": [
                        r"/components/com_",
                        r"/media/jui/",
                        r"<meta name=\"generator\" content=\"Joomla! ([0-9.]+)\">"
                    ]
                }
            },
            "js_frameworks": {
                "jQuery": {
                    "html": [
                        r"jquery(?:-|\.min\.js|\.js)",
                        r"jQuery v([0-9.]+)"
                    ]
                },
                "React": {
                    "html": [
                        r"react(?:-|\.min\.js|\.js)",
                        r"react-dom(?:-|\.min\.js|\.js)"
                    ]
                },
                "Angular": {
                    "html": [
                        r"angular(?:-|\.min\.js|\.js)",
                        r"ng-app",
                        r"ng-controller"
                    ]
                },
                "Vue.js": {
                    "html": [
                        r"vue(?:-|\.min\.js|\.js)",
                        r"v-app",
                        r"v-bind"
                    ]
                }
            },
            "analytics": {
                "Google Analytics": {
                    "html": [
                        r"google-analytics.com/analytics.js",
                        r"ga\('create',",
                        r"gtag\("
                    ]
                },
                "Google Tag Manager": {
                    "html": [
                        r"googletagmanager.com/gtm.js",
                        r"GTM-[A-Z0-9]+"
                    ]
                }
            }
        }
    
    def fingerprint(self, url):
        """
        Fingerprint technologies used by a website
        
        Args:
            url (str): URL of the website to fingerprint
        
        Returns:
            dict: Dictionary of identified technologies
        """
        print(f"Fingerprinting technologies for {url}")
        
        # Initialize results
        results = {
            "server": {},
            "cms": {},
            "js_frameworks": {},
            "web_frameworks": {},
            "analytics": {},
            "other": {}
        }
        
        try:
            # Make the request
            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            
            # Check response status
            if response.status_code != 200:
                print(f"Warning: Received status code {response.status_code}")
            
            # Extract information from headers
            self._extract_from_headers(response.headers, results)
            
            # Extract information from HTML content
            self._extract_from_html(response.text, results)
            
            # Use builtwith if available
            if self.has_builtwith:
                self._extract_from_builtwith(url, results)
            
            # Use webtech if available
            if self.has_webtech:
                self._extract_from_webtech(url, results)
            
        except requests.exceptions.RequestException as e:
            print(f"Error making request to {url}: {str(e)}")
        except Exception as e:
            print(f"Error fingerprinting {url}: {str(e)}")
        
        # Print results
        for category, techs in results.items():
            if techs:
                print(f"  {category.capitalize()}:")
                for tech, version in techs.items():
                    if version:
                        print(f"    - {tech} {version}")
                    else:
                        print(f"    - {tech}")
        
        return results
    
    def _extract_from_headers(self, headers, results):
        """Extract technology information from HTTP headers"""
        # Check for server software
        for server, signature in self.signatures["servers"].items():
            for header_name in signature["headers"]:
                if header_name in headers:
                    header_value = headers[header_name]
                    match = re.search(signature["regex"], header_value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else ""
                        results["server"][server] = version
        
        # Check for security headers
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "XSS Protection",
            "X-Content-Type-Options": "X-Content-Type-Options"
        }
        
        for header, tech in security_headers.items():
            if header in headers:
                results["other"][tech] = ""
        
        # Check for caching/CDN headers
        cdn_headers = {
            "CF-Cache-Status": "Cloudflare",
            "X-Cache": "Caching",
            "X-CDN": "CDN",
            "Fastly-Debug-Digest": "Fastly",
            "X-Amz-Cf-Id": "Amazon CloudFront"
        }
        
        for header, tech in cdn_headers.items():
            if header in headers:
                results["other"][tech] = ""
    
    def _extract_from_html(self, html, results):
        """Extract technology information from HTML content"""
        # Check for CMS
        for cms, signature in self.signatures["cms"].items():
            for pattern in signature["html"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else ""
                    results["cms"][cms] = version
                    break
        
        # Check for JS frameworks
        for framework, signature in self.signatures["js_frameworks"].items():
            for pattern in signature["html"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else ""
                    results["js_frameworks"][framework] = version
                    break
        
        # Check for analytics
        for analytics, signature in self.signatures["analytics"].items():
            for pattern in signature["html"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else ""
                    results["analytics"][analytics] = version
                    break
        
        # Check for web frameworks (simplified)
        framework_patterns = {
            "Laravel": [r"laravel", r"Laravel v([0-9.]+)"],
            "Django": [r"csrfmiddlewaretoken", r"__django"],
            "Ruby on Rails": [r"rails", r"csrf-token"],
            "Express.js": [r"express", r"x-powered-by: express"],
            "ASP.NET": [r"__VIEWSTATE", r"asp.net"],
            "Flask": [r"flask", r"Werkzeug"],
            "Spring": [r"spring", r"org.springframework"]
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    results["web_frameworks"][framework] = ""
                    break
    
    def _extract_from_builtwith(self, url, results):
        """Extract technology information using builtwith"""
        try:
            import builtwith
            technologies = builtwith.builtwith(url)
            
            # Map builtwith categories to our categories
            category_mapping = {
                "cms": "cms",
                "javascript-frameworks": "js_frameworks",
                "web-frameworks": "web_frameworks",
                "analytics": "analytics",
                "web-servers": "server"
            }
            
            for category, techs in technologies.items():
                mapped_category = category_mapping.get(category.lower(), "other")
                for tech in techs:
                    results[mapped_category][tech] = ""
        except Exception as e:
            print(f"Error using builtwith: {str(e)}")
    
    def _extract_from_webtech(self, url, results):
        """Extract technology information using webtech"""
        try:
            from webtech import WebTech
            wt = WebTech()
            report = wt.start_from_url(url)
            
            for tech in report.get('tech', []):
                name = tech.get('name', '')
                version = tech.get('version', '')
                category = tech.get('category', '').lower()
                
                if category == 'cms':
                    results["cms"][name] = version
                elif category in ['javascript', 'javascript framework']:
                    results["js_frameworks"][name] = version
                elif category in ['web framework', 'framework']:
                    results["web_frameworks"][name] = version
                elif category == 'web server':
                    results["server"][name] = version
                elif category == 'analytics':
                    results["analytics"][name] = version
                else:
                    results["other"][name] = version
        except Exception as e:
            print(f"Error using webtech: {str(e)}")

if __name__ == "__main__":
    import argparse
    import urllib3
    
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    parser = argparse.ArgumentParser(description='Technology fingerprinting tool')
    parser.add_argument('-u', '--url', required=True, help='URL to fingerprint')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-a', '--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Run the fingerprinter
    fingerprinter = TechFingerprinter(user_agent=args.user_agent if args.user_agent else None)
    results = fingerprinter.fingerprint(args.url)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {args.output}")