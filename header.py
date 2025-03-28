import requests

def fetch_http_headers(url):
    try:
        response = requests.head(url, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            print("\nHTTP Headers:")
            for key, value in response.headers.items():
                print(f"{key}: {value}")
        else:
            print(f"Error: Received status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    url = input("Enter URL: ")
    fetch_http_headers(url)
