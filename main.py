#!/usr/bin/env python3
"""
ReconSpider - Feature-rich External Reconnaissance Tool

This tool performs comprehensive reconnaissance on a target domain, including:
1. Advanced subdomain enumeration
2. Port and service scanning
3. Technology stack fingerprinting
4. Security misconfiguration checks
5. Threat intelligence integration
6. Website crawling and mapping
7. Reporting and visualization
8. Automation and scheduling

Usage:
    python main.py -d example.com [options]
"""

import argparse
import os
import sys
import json
import time
import logging
from datetime import datetime

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Print debug information
print(f"Python path: {sys.path}")
print(f"Current directory: {current_dir}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("reconspider.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ReconSpider")

# Import from individual files
try:
    from subdomain_enum import SubdomainEnumerator
    from port_scanner import PortScanner
    from tech_fingerprint import TechFingerprinter
    from security_checks import SecurityChecker
    from threat_intel import ThreatIntelligence
    from web_crawler import WebCrawler
    from reporting import ReportGenerator
    from visualization import Visualizer
    from scheduler import ReconScheduler
    print("Successfully imported all modules")
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

class ReconSpider:
    """Main class for the ReconSpider tool"""
    
    def __init__(self, args):
        """Initialize ReconSpider with command line arguments"""
        self.domain = args.domain
        self.output_dir = args.output_dir
        self.wordlist = args.wordlist
        self.threads = args.threads
        self.ports = args.ports
        self.scan_timeout = args.timeout
        self.report_format = args.report_format
        self.verbose = args.verbose
        self.schedule = args.schedule
        self.api_keys = self._load_api_keys(args.api_keys)
        
        # Web crawler parameters
        self.max_pages = args.max_pages
        self.max_depth = args.max_depth
        self.respect_robots = not args.no_robots
        self.crawl_delay = args.crawl_delay
        self.include_subdomains = args.include_subdomains
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Initialize results dictionary
        self.results = {
            "domain": self.domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "security_issues": [],
            "threat_intel": {},
            "crawl_data": {},
            "summary": {}
        }
        
        logger.info(f"Initializing ReconSpider for domain: {self.domain}")
    
    def _load_api_keys(self, api_keys_file):
        """Load API keys from a JSON file"""
        if not api_keys_file or not os.path.exists(api_keys_file):
            logger.warning("No API keys file provided or file not found. Some features may be limited.")
            return {}
        
        try:
            with open(api_keys_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading API keys: {str(e)}")
            return {}
    
    def run(self):
        """Run the reconnaissance process"""
        start_time = time.time()
        logger.info("Starting reconnaissance process")
        
        # Step 1: Subdomain Enumeration
        if not args.skip_subdomains:
            logger.info("Starting subdomain enumeration")
            subdomain_enumerator = SubdomainEnumerator(
                self.domain, 
                wordlist_path=self.wordlist,
                threads=self.threads,
                use_virustotal=bool(self.api_keys.get('virustotal')),
                use_threatcrowd=True,
                virustotal_api_key=self.api_keys.get('virustotal')
            )
            self.results["subdomains"] = subdomain_enumerator.enumerate()
            logger.info(f"Found {len(self.results['subdomains'])} subdomains")
        
        # Step 2: Port Scanning
        if not args.skip_ports:
            logger.info("Starting port scanning")
            port_scanner = PortScanner(
                threads=self.threads,
                timeout=self.scan_timeout
            )
            
            # Scan the main domain
            self.results["ports"][self.domain] = port_scanner.scan(self.domain, self.ports)
            
            # Scan subdomains if available
            for subdomain in self.results.get("subdomains", []):
                self.results["ports"][subdomain] = port_scanner.scan(subdomain, self.ports)
            
            logger.info("Port scanning completed")
        
        # Step 3: Technology Fingerprinting
        if not args.skip_tech:
            logger.info("Starting technology fingerprinting")
            tech_fingerprinter = TechFingerprinter()
            
            # Fingerprint the main domain
            self.results["technologies"][self.domain] = tech_fingerprinter.fingerprint(f"http://{self.domain}")
            
            # Try HTTPS if available
            try:
                https_tech = tech_fingerprinter.fingerprint(f"https://{self.domain}")
                self.results["technologies"][f"https://{self.domain}"] = https_tech
            except Exception as e:
                logger.debug(f"HTTPS fingerprinting failed for {self.domain}: {str(e)}")
            
            # Fingerprint subdomains
            for subdomain in self.results.get("subdomains", []):
                try:
                    self.results["technologies"][subdomain] = tech_fingerprinter.fingerprint(f"http://{subdomain}")
                except Exception as e:
                    logger.debug(f"Fingerprinting failed for {subdomain}: {str(e)}")
            
            logger.info("Technology fingerprinting completed")
        
        # Step 4: Security Checks
        if not args.skip_security:
            logger.info("Starting security checks")
            security_checker = SecurityChecker()
            
            # Check the main domain
            self.results["security_issues"] = security_checker.check(self.domain)
            
            # Check subdomains if available
            for subdomain in self.results.get("subdomains", []):
                subdomain_issues = security_checker.check(subdomain)
                if subdomain_issues:
                    self.results["security_issues"].extend(subdomain_issues)
            
            logger.info(f"Found {len(self.results['security_issues'])} security issues")
        
        # Step 5: Threat Intelligence
        if not args.skip_threat_intel and (self.api_keys.get('shodan') or self.api_keys.get('censys')):
            logger.info("Starting threat intelligence gathering")
            threat_intel = ThreatIntelligence(
                shodan_api_key=self.api_keys.get('shodan'),
                censys_api_id=self.api_keys.get('censys_id'),
                censys_api_secret=self.api_keys.get('censys_secret')
            )
            
            # Gather intel for the main domain
            self.results["threat_intel"][self.domain] = threat_intel.gather_intel(self.domain)
            
            # Gather intel for subdomains
            for subdomain in self.results.get("subdomains", []):
                self.results["threat_intel"][subdomain] = threat_intel.gather_intel(subdomain)
            
            logger.info("Threat intelligence gathering completed")
            
        # Step 6: Web Crawling
        if not args.skip_crawling:
            logger.info("Starting web crawling")
            web_crawler = WebCrawler(
                self.domain,
                max_pages=self.max_pages,
                max_depth=self.max_depth,
                threads=self.threads,
                respect_robots=self.respect_robots,
                delay=self.crawl_delay,
                timeout=self.scan_timeout,
                include_subdomains=self.include_subdomains
            )
            
            # Crawl the main domain
            self.results["crawl_data"] = web_crawler.crawl()
            
            logger.info(f"Web crawling completed: {self.results['crawl_data'].get('pages_crawled', 0)} pages crawled")
        
        # Generate summary
        self.results["summary"] = {
            "total_subdomains": len(self.results.get("subdomains", [])),
            "total_open_ports": sum(len(ports) for ports in self.results.get("ports", {}).values()),
            "total_security_issues": len(self.results.get("security_issues", [])),
            "total_pages_crawled": self.results.get("crawl_data", {}).get("pages_crawled", 0),
            "scan_duration": time.time() - start_time
        }
        
        # Save raw results to JSON
        results_file = os.path.join(self.output_dir, f"{self.domain}_results.json")
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Raw results saved to {results_file}")
        
        # Generate reports
        if not args.skip_reports:
            logger.info(f"Generating reports in formats: {self.report_format}")
            report_generator = ReportGenerator(self.results, self.output_dir)
            
            for report_format in self.report_format:
                report_path = report_generator.generate(report_format)
                logger.info(f"Report generated: {report_path}")
        
        # Generate visualization
        if not args.skip_visualization:
            logger.info("Generating visualization")
            visualizer = Visualizer(self.results, self.output_dir)
            viz_path = visualizer.generate()
            logger.info(f"Visualization generated: {viz_path}")
        
        # Schedule next scan if requested
        if self.schedule:
            logger.info(f"Scheduling next scan with interval: {self.schedule}")
            scheduler = ReconScheduler()
            scheduler.schedule(self.domain, self.schedule, vars(args))
        
        logger.info(f"Reconnaissance completed in {time.time() - start_time:.2f} seconds")
        
        return self.results

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="ReconSpider - Feature-rich External Reconnaissance Tool")
    
    # Required arguments
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    
    # Output options
    parser.add_argument("-o", "--output-dir", default="./output", help="Output directory for results and reports")
    parser.add_argument("-rf", "--report-format", nargs="+", default=["text", "html", "pdf"], 
                      choices=["text", "html", "pdf"], help="Report formats to generate")
    
    # Scan options
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent operations")
    parser.add_argument("-p", "--ports", default="21,22,25,53,80,110,143,443,445,3306,3389,8080,8443", 
                      help="Comma-separated list of ports to scan")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for network operations in seconds")
    
    # API keys
    parser.add_argument("-a", "--api-keys", help="Path to JSON file containing API keys")
    
    # Skip options
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-tech", action="store_true", help="Skip technology fingerprinting")
    parser.add_argument("--skip-security", action="store_true", help="Skip security checks")
    parser.add_argument("--skip-threat-intel", action="store_true", help="Skip threat intelligence gathering")
    parser.add_argument("--skip-crawling", action="store_true", help="Skip web crawling")
    parser.add_argument("--skip-reports", action="store_true", help="Skip report generation")
    parser.add_argument("--skip-visualization", action="store_true", help="Skip visualization generation")
    
    # Web crawler options
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum number of pages to crawl")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth to crawl")
    parser.add_argument("--no-robots", action="store_true", help="Ignore robots.txt rules")
    parser.add_argument("--crawl-delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--include-subdomains", action="store_true", help="Include subdomains in crawl")
    
    # Scheduling
    parser.add_argument("-s", "--schedule", help="Schedule recurring scans (format: 1h, 1d, 1w)")
    
    # Misc
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Initialize and run ReconSpider
        spider = ReconSpider(args)
        results = spider.run()
        
        # Print summary
        print("\n" + "="*50)
        print(f"RECONNAISSANCE SUMMARY FOR {args.domain}")
        print("="*50)
        print(f"Total subdomains found: {results['summary']['total_subdomains']}")
        print(f"Total open ports found: {results['summary']['total_open_ports']}")
        print(f"Total security issues found: {results['summary']['total_security_issues']}")
        print(f"Total pages crawled: {results['summary']['total_pages_crawled']}")
        print(f"Scan duration: {results['summary']['scan_duration']:.2f} seconds")
        print("="*50)
        print(f"Full results available in: {os.path.join(args.output_dir, f'{args.domain}_results.json')}")
        print("="*50)
        
        sys.exit(0)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)











