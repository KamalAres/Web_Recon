#!/usr/bin/env python3
"""
Unit tests for the Web Crawler module
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from web_crawler import WebCrawler

class TestWebCrawler(unittest.TestCase):
    """Test cases for the WebCrawler class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_domain = "example.com"
        self.test_url = f"https://{self.test_domain}"
        
        # Sample HTML content for testing
        self.sample_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Example Domain</title>
            <meta name="description" content="This is a test page">
            <link rel="stylesheet" href="/css/style.css">
            <script src="/js/script.js"></script>
        </head>
        <body>
            <h1>Example Domain</h1>
            <p>This domain is for use in illustrative examples in documents.</p>
            <div>
                <a href="https://example.com/page1">Page 1</a>
                <a href="/page2">Page 2</a>
                <a href="page3">Page 3</a>
                <a href="https://subdomain.example.com">Subdomain</a>
                <a href="https://external-site.com">External Site</a>
                <img src="/images/logo.png" alt="Logo">
            </div>
        </body>
        </html>
        """
    
    @patch('web_crawler.requests.get')
    def test_crawler_initialization(self, mock_get):
        """Test crawler initialization with different domain formats"""
        # Test with domain only
        crawler1 = WebCrawler("example.com")
        self.assertEqual(crawler1.base_url, "https://example.com")
        self.assertEqual(crawler1.domain, "example.com")
        
        # Test with http:// prefix
        crawler2 = WebCrawler("http://example.com")
        self.assertEqual(crawler2.base_url, "http://example.com")
        self.assertEqual(crawler2.domain, "example.com")
        
        # Test with https:// prefix
        crawler3 = WebCrawler("https://example.com")
        self.assertEqual(crawler3.base_url, "https://example.com")
        self.assertEqual(crawler3.domain, "example.com")
    
    @patch('web_crawler.requests.get')
    def test_robots_txt_parsing(self, mock_get):
        """Test parsing of robots.txt file"""
        # Mock robots.txt response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        User-agent: *
        Disallow: /private/
        Disallow: /admin/
        Allow: /public/
        """
        mock_get.return_value = mock_response
        
        crawler = WebCrawler("example.com", respect_robots=True)
        
        # Check if disallowed paths were parsed correctly
        self.assertEqual(len(crawler.disallowed_paths), 2)
        self.assertIn("/private/", crawler.disallowed_paths)
        self.assertIn("/admin/", crawler.disallowed_paths)
    
    def test_is_allowed(self):
        """Test URL permission checking based on robots.txt"""
        crawler = WebCrawler("example.com", respect_robots=True)
        
        # Manually set disallowed paths
        crawler.disallowed_paths = ["/private/", "/admin/"]
        
        # Test allowed URLs
        self.assertTrue(crawler._is_allowed("https://example.com"))
        self.assertTrue(crawler._is_allowed("https://example.com/public/page"))
        
        # Test disallowed URLs
        self.assertFalse(crawler._is_allowed("https://example.com/private/page"))
        self.assertFalse(crawler._is_allowed("https://example.com/admin/login"))
    
    def test_is_valid_url(self):
        """Test URL validation logic"""
        crawler = WebCrawler("example.com", include_subdomains=False)
        
        # Test valid URLs
        self.assertTrue(crawler._is_valid_url("https://example.com/page"))
        self.assertTrue(crawler._is_valid_url("https://example.com/path/to/page"))
        
        # Test invalid URLs (different domain)
        self.assertFalse(crawler._is_valid_url("https://different-domain.com"))
        
        # Test subdomain handling
        self.assertFalse(crawler._is_valid_url("https://sub.example.com"))
        
        # Test with subdomains enabled
        crawler_with_subs = WebCrawler("example.com", include_subdomains=True)
        self.assertTrue(crawler_with_subs._is_valid_url("https://sub.example.com"))
        
        # Test resource URLs (should be added to resources, not crawled)
        self.assertFalse(crawler._is_valid_url("https://example.com/image.jpg"))
        self.assertFalse(crawler._is_valid_url("https://example.com/document.pdf"))
    
    @patch('web_crawler.requests.get')
    def test_extract_links(self, mock_get):
        """Test link extraction from HTML content"""
        crawler = WebCrawler("example.com")
        
        # Extract links from sample HTML
        links = crawler._extract_links(self.test_url, self.sample_html, 0)
        
        # Check if links were extracted correctly
        self.assertEqual(len(links), 3)  # 3 valid links to crawl
        
        # Check if site map was updated
        self.assertEqual(len(crawler.site_map[self.test_url]), 3)
        
        # Check if resources were extracted
        self.assertEqual(len(crawler.resources['images']), 1)
        self.assertEqual(len(crawler.resources['scripts']), 1)
        self.assertEqual(len(crawler.resources['stylesheets']), 1)
        
        # Check if page data was stored
        self.assertIn(self.test_url, crawler.url_data)
        self.assertEqual(crawler.url_data[self.test_url]['title'], "Example Domain")
        self.assertEqual(crawler.url_data[self.test_url]['description'], "This is a test page")
    
    @patch('web_crawler.WebCrawler._crawl_url')
    def test_crawl(self, mock_crawl_url):
        """Test the main crawl method"""
        # Setup mock to return some links on first call, none on subsequent calls
        mock_crawl_url.side_effect = [
            [("https://example.com/page1", 1), ("https://example.com/page2", 1)],
            [],
            []
        ]
        
        crawler = WebCrawler("example.com", max_pages=10, threads=1)
        results = crawler.crawl()
        
        # Check if crawl was called the expected number of times
        self.assertEqual(mock_crawl_url.call_count, 3)
        
        # Check if results contain expected keys
        self.assertIn('domain', results)
        self.assertIn('base_url', results)
        self.assertIn('pages_crawled', results)
        self.assertIn('site_map', results)
        self.assertIn('resources', results)
        self.assertIn('page_data', results)

if __name__ == '__main__':
    unittest.main()