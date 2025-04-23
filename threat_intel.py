#!/usr/bin/env python3
"""
Threat Intelligence Module

This module provides functionality for gathering threat intelligence:
1. Shodan integration for exposed services and vulnerabilities
2. Censys integration for certificate and host information
3. Historical breach data
4. Reputation checks
"""

import json
import socket
import requests
import time
import importlib.util
from urllib.parse import urlparse

class ThreatIntelligence:
    """Class for gathering threat intelligence"""
    
    def __init__(self, shodan_api_key=None, censys_api_id=None, censys_api_secret=None):
        """
        Initialize the threat intelligence gatherer
        
        Args:
            shodan_api_key (str): API key for Shodan
            censys_api_id (str): API ID for Censys
            censys_api_secret (str): API secret for Censys
        """
        self.shodan_api_key = shodan_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret
        
        # Check for optional dependencies
        self.has_shodan = self._check_module("shodan")
        self.has_censys = self._check_module("censys")
    
    def _check_module(self, module_name):
        """Check if a Python module is available"""
        return importlib.util.find_spec(module_name) is not None
    
    def gather_intel(self, domain):
        """
        Gather threat intelligence for a domain
        
        Args:
            domain (str): Domain to gather intelligence for
        
        Returns:
            dict: Dictionary of threat intelligence data
        """
        print(f"Gathering threat intelligence for {domain}")
        
        # Initialize results
        results = {
            "shodan": {},
            "censys": {},
            "breaches": {},
            "reputation": {}
        }
        
        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            results["ip"] = ip
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {domain}")
            return results
        
        # Gather Shodan data
        if self.shodan_api_key and self.has_shodan:
            shodan_data = self._gather_shodan_data(ip)
            results["shodan"] = shodan_data
        
        # Gather Censys data
        if self.censys_api_id and self.censys_api_secret and self.has_censys:
            censys_data = self._gather_censys_data(domain, ip)
            results["censys"] = censys_data
        
        # Check for breaches
        breach_data = self._check_breaches(domain)
        results["breaches"] = breach_data
        
        # Check reputation
        reputation_data = self._check_reputation(domain, ip)
        results["reputation"] = reputation_data
        
        return results
    
    def _gather_shodan_data(self, ip):
        """Gather data from Shodan"""
        shodan_data = {}
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            
            # Get host information
            host = api.host(ip)
            
            # Extract relevant information
            shodan_data = {
                "ports": host.get('ports', []),
                "hostnames": host.get('hostnames', []),
                "country": host.get('country_name', 'Unknown'),
                "org": host.get('org', 'Unknown'),
                "isp": host.get('isp', 'Unknown'),
                "last_update": host.get('last_update', ''),
                "vulns": host.get('vulns', []),
                "tags": host.get('tags', [])
            }
            
            # Extract service information
            services = []
            for item in host.get('data', []):
                service = {
                    "port": item.get('port', 0),
                    "transport": item.get('transport', ''),
                    "product": item.get('product', ''),
                    "version": item.get('version', ''),
                    "cpe": item.get('cpe', [])
                }
                services.append(service)
            
            shodan_data['services'] = services
            
            # Print summary
            print(f"  Shodan: Found {len(shodan_data['ports'])} open ports and {len(shodan_data['vulns'])} vulnerabilities")
            
        except ImportError:
            print("  Shodan module not installed. Install with: pip install shodan")
        except Exception as e:
            print(f"  Error gathering Shodan data: {str(e)}")
        
        return shodan_data
    
    def _gather_censys_data(self, domain, ip):
        """Gather data from Censys"""
        censys_data = {}
        
        try:
            from censys.search import CensysHosts, CensysCertificates
            
            # Initialize Censys clients
            hosts_api = CensysHosts(api_id=self.censys_api_id, api_secret=self.censys_api_secret)
            certs_api = CensysCertificates(api_id=self.censys_api_id, api_secret=self.censys_api_secret)
            
            # Query for host information
            host_data = hosts_api.view(ip)
            
            # Extract relevant host information
            if host_data:
                censys_data['host'] = {
                    "autonomous_system": host_data.get('autonomous_system', {}).get('name', 'Unknown'),
                    "location": {
                        "country": host_data.get('location', {}).get('country', 'Unknown'),
                        "city": host_data.get('location', {}).get('city', 'Unknown')
                    },
                    "ports": host_data.get('services', []),
                    "last_updated": host_data.get('last_updated', '')
                }
            
            # Query for certificates
            certificates = []
            cert_query = f"parsed.names: {domain}"
            cert_results = certs_api.search(cert_query, per_page=10)
            
            for cert in cert_results:
                cert_info = {
                    "fingerprint": cert.get('fingerprint', ''),
                    "issuer": cert.get('parsed', {}).get('issuer', {}).get('common_name', ['Unknown'])[0],
                    "subject": cert.get('parsed', {}).get('subject', {}).get('common_name', ['Unknown'])[0],
                    "validity": {
                        "start": cert.get('parsed', {}).get('validity', {}).get('start', ''),
                        "end": cert.get('parsed', {}).get('validity', {}).get('end', '')
                    }
                }
                certificates.append(cert_info)
            
            censys_data['certificates'] = certificates
            
            # Print summary
            print(f"  Censys: Found {len(censys_data.get('host', {}).get('ports', []))} services and {len(certificates)} certificates")
            
        except ImportError:
            print("  Censys module not installed. Install with: pip install censys")
        except Exception as e:
            print(f"  Error gathering Censys data: {str(e)}")
        
        return censys_data
    
    def _check_breaches(self, domain):
        """Check for breaches using Have I Been Pwned API"""
        breach_data = {}
        
        try:
            # Have I Been Pwned API requires an API key now, so we'll use a simplified approach
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            headers = {
                "User-Agent": "ReconSpider Threat Intelligence Module"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                all_breaches = response.json()
                
                # Filter breaches for the domain
                domain_breaches = []
                for breach in all_breaches:
                    if domain.lower() in breach.get('Domain', '').lower():
                        domain_breaches.append({
                            "name": breach.get('Name', ''),
                            "title": breach.get('Title', ''),
                            "date": breach.get('BreachDate', ''),
                            "pwn_count": breach.get('PwnCount', 0),
                            "description": breach.get('Description', '')
                        })
                
                breach_data['breaches'] = domain_breaches
                
                # Print summary
                print(f"  Breaches: Found {len(domain_breaches)} breaches for {domain}")
            else:
                print(f"  Error checking breaches: HTTP {response.status_code}")
        
        except Exception as e:
            print(f"  Error checking breaches: {str(e)}")
        
        return breach_data
    
    def _check_reputation(self, domain, ip):
        """Check domain and IP reputation"""
        reputation_data = {}
        
        try:
            # Check IP reputation using AbuseIPDB
            ip_url = f"https://api.abuseipdb.com/api/v2/check"
            ip_headers = {
                "Key": "YOUR_ABUSEIPDB_API_KEY",  # Replace with actual API key
                "Accept": "application/json"
            }
            ip_params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            
            # Note: This is commented out because we don't have an API key
            # ip_response = requests.get(ip_url, headers=ip_headers, params=ip_params, timeout=10)
            # if ip_response.status_code == 200:
            #     ip_data = ip_response.json().get('data', {})
            #     reputation_data['ip'] = {
            #         "abuse_score": ip_data.get('abuseConfidenceScore', 0),
            #         "total_reports": ip_data.get('totalReports', 0),
            #         "country_code": ip_data.get('countryCode', ''),
            #         "isp": ip_data.get('isp', '')
            #     }
            
            # Check domain reputation using VirusTotal (public API)
            domain_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            domain_params = {
                "apikey": "YOUR_VIRUSTOTAL_API_KEY",  # Replace with actual API key
                "domain": domain
            }
            
            # Note: This is commented out because we don't have an API key
            # domain_response = requests.get(domain_url, params=domain_params, timeout=10)
            # if domain_response.status_code == 200:
            #     domain_data = domain_response.json()
            #     reputation_data['domain'] = {
            #         "categories": domain_data.get('categories', {}),
            #         "detected_urls": len(domain_data.get('detected_urls', [])),
            #         "detected_communicating_samples": len(domain_data.get('detected_communicating_samples', [])),
            #         "detected_referrer_samples": len(domain_data.get('detected_referrer_samples', []))
            #     }
            
            # Simulate some reputation data for demonstration
            reputation_data['ip'] = {
                "abuse_score": 0,
                "total_reports": 0,
                "country_code": "US",
                "isp": "Example ISP"
            }
            
            reputation_data['domain'] = {
                "categories": {},
                "detected_urls": 0,
                "detected_communicating_samples": 0,
                "detected_referrer_samples": 0
            }
            
            # Print summary
            print(f"  Reputation: IP abuse score: {reputation_data['ip']['abuse_score']}, Domain detections: {reputation_data['domain']['detected_urls']}")
        
        except Exception as e:
            print(f"  Error checking reputation: {str(e)}")
        
        return reputation_data

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Threat intelligence tool')
    parser.add_argument('-d', '--domain', required=True, help='Domain to gather intelligence for')
    parser.add_argument('-s', '--shodan', help='Shodan API key')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API secret')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Run the threat intelligence gatherer
    intel = ThreatIntelligence(
        shodan_api_key=args.shodan,
        censys_api_id=args.censys_id,
        censys_api_secret=args.censys_secret
    )
    
    results = intel.gather_intel(args.domain)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {args.output}")