#!/usr/bin/env python3
"""
Test the create_modules.py script to ensure it correctly creates the modules directory
and initializes it as a Python package.
"""

import os
import shutil
import unittest
from create_modules import create_modules_structure

class TestCreateModules(unittest.TestCase):
    """Test cases for the create_modules.py script."""
    
    def setUp(self):
        """Set up the test environment."""
        # Define the path to the modules directory
        self.modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules')
        
        # Remove the modules directory if it exists
        if os.path.exists(self.modules_dir):
            shutil.rmtree(self.modules_dir)
    
    def tearDown(self):
        """Clean up after the test."""
        # Remove the modules directory if it exists
        if os.path.exists(self.modules_dir):
            shutil.rmtree(self.modules_dir)
    
    def test_create_modules_structure(self):
        """Test that the create_modules_structure function works correctly."""
        # Call the function
        create_modules_structure()
        
        # Check that the modules directory exists
        self.assertTrue(os.path.exists(self.modules_dir), "Modules directory was not created")
        self.assertTrue(os.path.isdir(self.modules_dir), "Modules path is not a directory")
        
        # Check that the __init__.py file exists
        init_file = os.path.join(self.modules_dir, '__init__.py')
        self.assertTrue(os.path.exists(init_file), "__init__.py file was not created")
        
        # Check the content of the __init__.py file
        with open(init_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, '"""ReconSpider modules package"""', 
                         "__init__.py file has incorrect content")

if __name__ == "__main__":
    unittest.main()