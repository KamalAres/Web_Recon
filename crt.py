import requests
import json
import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_subdomains_from_crt(hostname):
    """
    Get subdomains using certificate transparency logs from crt.sh
    """
    url = f"https://crt.sh/?q={hostname}&output=json"
    try:
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            data = response.json()
            subdomains = sorted(set(entry["name_value"] for entry in data if "name_value" in entry))
            return subdomains
        else:
            return [f"Error: Unable to fetch data, status code {response.status_code}"]
    except requests.exceptions.RequestException as e:
        return [f"Error: {e}"]

def is_subdomain_resolvable(subdomain):
    """
    Check if a subdomain resolves to an IP address
    """
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False

def get_subdomains_from_wordlist(hostname, wordlist_path=None):
    """
    Get subdomains by trying common subdomain names from a wordlist
    """
    # Use default wordlist if none provided
    if not wordlist_path or not os.path.exists(wordlist_path):
        wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'default_subdomains.txt')
        if not os.path.exists(wordlist_path):
            return [f"Error: Default wordlist not found at {wordlist_path}"]
    
    try:
        with open(wordlist_path, 'r') as f:
            prefixes = [line.strip() for line in f if line.strip()]
    except Exception as e:
        return [f"Error: Failed to read wordlist - {str(e)}"]
    
    valid_subdomains = []
    potential_subdomains = [f"{prefix}.{hostname}" for prefix in prefixes]
    
    print(f"Testing {len(potential_subdomains)} potential subdomains...")
    
    # Use ThreadPoolExecutor for parallel resolution
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(is_subdomain_resolvable, subdomain): subdomain for subdomain in potential_subdomains}
        
        # Process results as they complete
        for i, future in enumerate(as_completed(future_to_subdomain)):
            subdomain = future_to_subdomain[future]
            if i % 10 == 0:  # Progress update every 10 subdomains
                print(f"Progress: {i}/{len(potential_subdomains)} subdomains tested")
            try:
                if future.result():
                    valid_subdomains.append(subdomain)
                    print(f"Found valid subdomain: {subdomain}")
            except Exception as e:
                print(f"Error checking {subdomain}: {str(e)}")
    
    return sorted(valid_subdomains)

def get_subdomains(hostname, method='crt', wordlist_path=None):
    """
    Get subdomains using the specified method
    """
    if method.lower() == 'wordlist':
        return get_subdomains_from_wordlist(hostname, wordlist_path)
    else:  # Default to crt.sh
        return get_subdomains_from_crt(hostname)

if __name__ == "__main__":
    hostname = input("Enter hostname (e.g., example.com): ")
    
    print("\nSelect subdomain enumeration method:")
    print("1. Certificate Transparency Logs (crt.sh)")
    print("2. Wordlist-based enumeration")
    
    choice = input("\nEnter your choice (1 or 2): ")
    
    if choice == '2':
        custom_wordlist = input("\nEnter path to custom wordlist (leave empty for default): ")
        if custom_wordlist and not os.path.exists(custom_wordlist):
            print(f"Warning: Wordlist not found at {custom_wordlist}, using default wordlist")
            custom_wordlist = None
        
        print("\nEnumerating subdomains using wordlist...")
        subdomains = get_subdomains(hostname, method='wordlist', wordlist_path=custom_wordlist)
    else:
        print("\nEnumerating subdomains using certificate transparency logs...")
        subdomains = get_subdomains(hostname, method='crt')
    
    print("\nSubdomains found:")
    print(f"Number of subdomains found: {len(subdomains)}")
    for subdomain in subdomains:
        print(subdomain)