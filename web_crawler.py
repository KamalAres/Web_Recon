#!/usr/bin/env python3
"""
Web Crawler Module

This module provides functionality for crawling websites and extracting information:
1. URL discovery and mapping
2. Site structure analysis
3. Content extraction
4. Link relationship mapping
5. Resource identification (images, scripts, stylesheets)
"""

import os
import sys
import time
import json
import logging
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import re
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WebCrawler")

class WebCrawler:
    """Class for crawling websites and extracting information"""
    
    def __init__(self, domain, max_pages=100, max_depth=3, threads=10, 
                 respect_robots=True, delay=0.5, timeout=10, user_agent=None,
                 include_subdomains=False):
        """
        Initialize the web crawler
        
        Args:
            domain (str): The target domain to crawl (e.g., example.com)
            max_pages (int): Maximum number of pages to crawl
            max_depth (int): Maximum depth to crawl
            threads (int): Number of concurrent threads to use
            respect_robots (bool): Whether to respect robots.txt
            delay (float): Delay between requests in seconds
            timeout (int): Request timeout in seconds
            user_agent (str): Custom user agent string
            include_subdomains (bool): Whether to include subdomains in crawl
        """
        # Ensure domain has a scheme
        if not domain.startswith(('http://', 'https://')):
            self.base_url = f"https://{domain}"
        else:
            self.base_url = domain
            
        # Extract the domain from the URL
        parsed_url = urlparse(self.base_url)
        self.domain = parsed_url.netloc
        
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.threads = threads
        self.respect_robots = respect_robots
        self.delay = delay
        self.timeout = timeout
        self.include_subdomains = include_subdomains
        
        # Set user agent
        self.user_agent = user_agent or 'ReconSpider WebCrawler/1.0'
        
        # Initialize data structures
        self.visited_urls = set()
        self.urls_to_visit = []
        self.url_data = {}
        self.site_map = defaultdict(list)
        self.resources = defaultdict(list)
        self.disallowed_paths = []
        
        # Headers for requests
        self.headers = {
            'User-Agent': self.user_agent
        }
        
        # If respecting robots.txt, parse it
        if self.respect_robots:
            self._parse_robots_txt()
    
    def _parse_robots_txt(self):
        """Parse robots.txt file to respect crawling rules"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            response = requests.get(robots_url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                user_agent_applies = False
                
                for line in lines:
                    line = line.strip().lower()
                    
                    # Check if this section applies to our user agent
                    if line.startswith('user-agent:'):
                        agent = line[11:].strip()
                        user_agent_applies = (agent == '*' or self.user_agent.lower().find(agent) != -1)
                    
                    # If this section applies to us and it's a disallow rule, add it
                    if user_agent_applies and line.startswith('disallow:'):
                        path = line[9:].strip()
                        if path:
                            self.disallowed_paths.append(path)
                            
                logger.info(f"Parsed robots.txt: {len(self.disallowed_paths)} disallowed paths")
        except Exception as e:
            logger.warning(f"Error parsing robots.txt: {str(e)}")
    
    def _is_allowed(self, url):
        """Check if URL is allowed to be crawled based on robots.txt"""
        if not self.respect_robots:
            return True
            
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
                
        return True
    
    def _is_valid_url(self, url):
        """Check if URL is valid and should be crawled"""
        try:
            parsed_url = urlparse(url)
            
            # Check if URL is within scope (same domain or subdomain if enabled)
            if self.include_subdomains:
                if not parsed_url.netloc.endswith(self.domain):
                    return False
            else:
                if parsed_url.netloc != self.domain:
                    return False
            
            # Check if URL has already been visited
            if url in self.visited_urls:
                return False
                
            # Check if URL is allowed by robots.txt
            if not self._is_allowed(url):
                return False
                
            # Only crawl web pages, not other resources
            if parsed_url.path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar.gz')):
                # Add to resources instead
                resource_type = os.path.splitext(parsed_url.path)[1][1:] or 'unknown'
                self.resources[resource_type].append(url)
                return False
                
            return True
        except Exception:
            return False
    
    def _extract_links(self, url, html_content, depth):
        """Extract links from HTML content"""
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract page title
            title = soup.title.string if soup.title else "No Title"
            
            # Extract meta description
            meta_desc = ""
            meta_tag = soup.find('meta', attrs={'name': 'description'})
            if meta_tag:
                meta_desc = meta_tag.get('content', '')
            
            # Extract all links
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                
                # Convert relative URLs to absolute
                if not link.startswith(('http://', 'https://')):
                    link = urljoin(url, link)
                
                # Check if link is valid
                if self._is_valid_url(link):
                    links.append((link, depth + 1))
                    # Add to site map
                    self.site_map[url].append(link)
            
            # Extract resources (images, scripts, stylesheets)
            for img in soup.find_all('img', src=True):
                img_url = urljoin(url, img['src'])
                self.resources['images'].append(img_url)
                
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                self.resources['scripts'].append(script_url)
                
            for link in soup.find_all('link', href=True):
                if link.get('rel') and 'stylesheet' in link.get('rel'):
                    css_url = urljoin(url, link['href'])
                    self.resources['stylesheets'].append(css_url)
            
            # Store page data
            self.url_data[url] = {
                'title': title,
                'description': meta_desc,
                'depth': depth,
                'links_count': len(links),
                'content_length': len(html_content)
            }
            
            return links
        except Exception as e:
            logger.error(f"Error extracting links from {url}: {str(e)}")
            return []
    
    def _crawl_url(self, url_info):
        """Crawl a single URL and extract information"""
        url, depth = url_info
        
        # Check if we've reached max depth
        if depth > self.max_depth:
            return []
            
        # Check if we've already visited this URL
        if url in self.visited_urls:
            return []
            
        # Add to visited URLs
        self.visited_urls.add(url)
        
        # Respect the crawl delay
        time.sleep(self.delay)
        
        try:
            logger.info(f"Crawling: {url} (depth: {depth})")
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            # Only process successful responses
            if response.status_code == 200:
                # Check if it's HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    return self._extract_links(url, response.text, depth)
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            
        return []
    
    def crawl(self):
        """
        Crawl the website starting from the base URL
        
        Returns:
            dict: Crawl results including site map, resources, and page data
        """
        logger.info(f"Starting web crawl for {self.base_url}")
        
        # Start with the base URL at depth 0
        self.urls_to_visit = [(self.base_url, 0)]
        
        # Use ThreadPoolExecutor for parallel crawling
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while self.urls_to_visit and len(self.visited_urls) < self.max_pages:
                # Get a batch of URLs to crawl (limited by thread count)
                batch_size = min(self.threads, len(self.urls_to_visit))
                batch = [self.urls_to_visit.pop(0) for _ in range(batch_size)]
                
                # Submit crawl tasks
                future_to_url = {executor.submit(self._crawl_url, url_info): url_info for url_info in batch}
                
                # Process results and add new URLs to visit
                for future in future_to_url:
                    try:
                        new_links = future.result()
                        for link in new_links:
                            if link[0] not in self.visited_urls and link not in self.urls_to_visit:
                                self.urls_to_visit.append(link)
                    except Exception as e:
                        logger.error(f"Error processing crawl result: {str(e)}")
        
        # Prepare results
        results = {
            'domain': self.domain,
            'base_url': self.base_url,
            'pages_crawled': len(self.visited_urls),
            'site_map': dict(self.site_map),
            'resources': dict(self.resources),
            'page_data': self.url_data
        }
        
        logger.info(f"Crawl completed: {len(self.visited_urls)} pages crawled")
        return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Web Crawler Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain to crawl (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-m', '--max-pages', type=int, default=100, help='Maximum number of pages to crawl')
    parser.add_argument('-p', '--max-depth', type=int, default=3, help='Maximum depth to crawl')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds')
    parser.add_argument('--include-subdomains', action='store_true', help='Include subdomains in crawl')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Run the crawler
    crawler = WebCrawler(
        args.domain,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        threads=args.threads,
        respect_robots=not args.no_robots,
        delay=args.delay,
        include_subdomains=args.include_subdomains
    )
    
    results = crawler.crawl()
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=4))