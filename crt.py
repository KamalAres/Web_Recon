import requests
import json

def get_subdomains(hostname):
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

if __name__ == "__main__":
    hostname = input("Enter hostname: ")
    subdomains = get_subdomains(hostname)
    print("\nSubdomains found:")
    print(f"\nNumber of subdomains found: {len(subdomains)}")
    for subdomain in subdomains:
        print(subdomain)

