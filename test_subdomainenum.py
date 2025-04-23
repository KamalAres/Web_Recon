#!/usr/bin/env python3
"""
Unit tests for the subdomain enumeration tool
"""

import unittest
from unittest.mock import patch, MagicMock
import io
import sys
import os
import tempfile
from contextlib import redirect_stdout

# Import the module to test
import subdomainenum

class TestSubdomainEnum(unittest.TestCase):
    """Test cases for the subdomain enumeration tool"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary test wordlist using tempfile for cross-platform compatibility
        fd, self.test_wordlist = tempfile.mkstemp(suffix=".txt", prefix="test_wordlist_")
        with os.fdopen(fd, 'w') as f:
            f.write("www\nmail\ntest\nadmin\n")
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary test wordlist
        if os.path.exists(self.test_wordlist):
            os.remove(self.test_wordlist)
    
    @patch('subdomainenum.is_subdomain_resolvable')
    def test_enumerate_subdomains(self, mock_resolve):
        """Test the subdomain enumeration function"""
        # Mock the resolution function to return True for specific subdomains
        def mock_resolution(subdomain):
            return subdomain in ["www.example.com", "admin.example.com"]
        
        mock_resolve.side_effect = mock_resolution
        
        # Capture stdout to verify output
        f = io.StringIO()
        with redirect_stdout(f):
            result = subdomainenum.enumerate_subdomains("example.com", self.test_wordlist, threads=2, verbose=True)
        
        # Check the results
        self.assertEqual(len(result), 2)
        self.assertIn("www.example.com", result)
        self.assertIn("admin.example.com", result)
        self.assertNotIn("mail.example.com", result)
        self.assertNotIn("test.example.com", result)
        
        # Check that the output contains the valid subdomains
        output = f.getvalue()
        self.assertIn("www.example.com", output)
        self.assertIn("admin.example.com", output)
    
    @patch('subdomainenum.is_subdomain_resolvable')
    def test_nonexistent_wordlist(self, mock_resolve):
        """Test behavior with a non-existent wordlist"""
        with self.assertRaises(SystemExit):
            subdomainenum.enumerate_subdomains("example.com", "/nonexistent/path.txt")
    
    @patch('subdomainenum.enumerate_subdomains')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_function(self, mock_args, mock_enumerate):
        """Test the main function with command line arguments"""
        # Mock command line arguments
        mock_args.return_value = MagicMock(
            domain="example.com",
            wordlist=self.test_wordlist,
            threads=5,
            verbose=True
        )
        
        # Run the main function
        subdomainenum.main()
        
        # Verify that enumerate_subdomains was called with the correct arguments
        mock_enumerate.assert_called_once_with(
            "example.com", 
            self.test_wordlist, 
            5, 
            True
        )

if __name__ == "__main__":
    unittest.main()
