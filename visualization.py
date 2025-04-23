#!/usr/bin/env python3
"""
Visualization Module

This module provides functionality for visualizing reconnaissance results.
"""

import os
import json
import importlib.util

class Visualizer:
    """Class for visualizing reconnaissance results"""
    
    def __init__(self, results, output_dir):
        """
        Initialize the visualizer
        
        Args:
            results (dict): Results data to visualize
            output_dir (str): Directory to save visualizations
        """
        self.results = results
        self.output_dir = output_dir
        
        # Check for optional dependencies
        self.has_matplotlib = self._check_module("matplotlib")
        self.has_networkx = self._check_module("networkx")
    
    def _check_module(self, module_name):
        """Check if a Python module is available"""
        return importlib.util.find_spec(module_name) is not None
    
    def generate(self):
        """
        Generate visualizations
        
        Returns:
            str: Path to the generated visualization
        """
        if self.has_networkx and self.has_matplotlib:
            return self._generate_network_graph()
        else:
            print("Warning: matplotlib and/or networkx not installed. Skipping visualization.")
            return None
    
    def _generate_network_graph(self):
        """Generate a network graph visualization"""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Create a new graph
            G = nx.Graph()
            
            # Add the main domain as the central node
            main_domain = self.results.get("domain", "unknown")
            G.add_node(main_domain, type="main_domain")
            
            # Add subdomains
            for subdomain in self.results.get("subdomains", []):
                G.add_node(subdomain, type="subdomain")
                G.add_edge(main_domain, subdomain)
            
            # Add ports to respective domains
            for domain, ports in self.results.get("ports", {}).items():
                for port, info in ports.items():
                    port_label = f"{port}/{info.get('service', 'unknown')}"
                    G.add_node(port_label, type="port")
                    G.add_edge(domain, port_label)
            
            # Add security issues
            for issue in self.results.get("security_issues", []):
                issue_label = issue.get("title", "Unknown Issue")
                url = issue.get("url", "")
                if url:
                    domain = url.split("//")[-1].split("/")[0]
                    G.add_node(issue_label, type="issue")
                    G.add_edge(domain, issue_label)
            
            # Set up the plot
            plt.figure(figsize=(12, 8))
            
            # Define node positions using spring layout
            pos = nx.spring_layout(G, k=0.5, iterations=50)
            
            # Define node colors based on type
            node_colors = []
            for node in G.nodes():
                node_type = G.nodes[node].get("type", "")
                if node_type == "main_domain":
                    node_colors.append("red")
                elif node_type == "subdomain":
                    node_colors.append("blue")
                elif node_type == "port":
                    node_colors.append("green")
                elif node_type == "issue":
                    node_colors.append("orange")
                else:
                    node_colors.append("gray")
            
            # Draw the graph
            nx.draw(G, pos, with_labels=True, node_color=node_colors, 
                   node_size=500, font_size=8, font_weight="bold", 
                   edge_color="gray", linewidths=0.5, alpha=0.8)
            
            # Save the figure
            output_path = os.path.join(self.output_dir, f"{main_domain}_network_graph.png")
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()
            
            print(f"Network graph visualization saved to {output_path}")
            return output_path
            
        except Exception as e:
            print(f"Error generating network graph: {str(e)}")
            return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Visualization tool')
    parser.add_argument('-i', '--input', required=True, help='Input JSON results file')
    parser.add_argument('-o', '--output-dir', default="./output", help='Output directory for visualizations')
    
    args = parser.parse_args()
    
    # Load results from JSON file
    try:
        with open(args.input, 'r') as f:
            results = json.load(f)
    except Exception as e:
        print(f"Error loading results file: {str(e)}")
        exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate visualizations
    visualizer = Visualizer(results, args.output_dir)
    visualizer.generate()