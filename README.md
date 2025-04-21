# ReconSpider: Comprehensive Web Reconnaissance and Security Analysis Tool

ReconSpider is a powerful Python-based web reconnaissance tool that combines web crawling, security header analysis, and domain intelligence gathering capabilities. It helps security professionals and developers assess website security posture, discover potential vulnerabilities, and gather comprehensive information about web applications.

The tool provides automated scanning of websites to extract valuable information including security headers, CORS configurations, subdomains, and various web assets while performing security checks. ReconSpider features intelligent crawling that respects domain boundaries, comprehensive header analysis, and detailed reporting of findings in structured JSON format.

## Repository Structure
```
.
├── crt.py                  # Certificate transparency log scanner and wordlist-based subdomain enumeration
├── header.py              # HTTP header analyzer for security assessment
├── recon.py              # Core security header and CORS analysis functionality
├── ReconSpider/          # Main web crawler implementation directory
│   └── ReconSpider.py    # Scrapy-based intelligent web crawler
├── default_subdomains.txt # Default wordlist for subdomain enumeration
├── subdomainenum.py      # Dedicated CLI tool for subdomain enumeration (Gobuster-like)
└── results.json          # Output file containing crawling results and findings
```

## Usage Instructions
### Prerequisites
- Python 3.7+
- pip package manager
- Required Python packages:
  - requests
  - scrapy
  - urllib3

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/ReconSpider.git
cd ReconSpider

# Install required packages
pip install -r requirements.txt
```

### Quick Start
1. Basic website reconnaissance:
```bash
python recon.py
# Enter website URL when prompted (including http/https)
```

2. Analyze HTTP headers:
```bash
python header.py
# Enter target URL when prompted
```

3. Discover subdomains using certificate transparency or wordlist:
```bash
python crt.py
# Enter hostname when prompted
# Choose between certificate transparency logs or wordlist-based enumeration
```

4. Subdomain enumeration (Gobuster-like):
```bash
python subdomainenum.py -d example.com -w default_subdomains.txt
# Use -t to specify number of threads
# Use -v for verbose output
```

5. Full website crawling and analysis:
```bash
python ReconSpider/ReconSpider.py https://example.com
# Add --enum-subdomains to perform subdomain enumeration
# Add --wordlist /path/to/wordlist.txt to use a custom wordlist for subdomain enumeration
```

### More Detailed Examples

1. Security Header Analysis:
```python
# Check security headers for a specific website
python recon.py
Enter website URL (including http/https): https://example.com

# Output will show presence/absence of security headers:
✅ Strict-Transport-Security: Present
❌ Content-Security-Policy: Missing - CSP helps prevent XSS attacks
```

2. Subdomain Discovery (using crt.py):
```python
python crt.py
Enter hostname (e.g., example.com): example.com

Select subdomain enumeration method:
1. Certificate Transparency Logs (crt.sh)
2. Wordlist-based enumeration

Enter your choice (1 or 2): 2
Enter path to custom wordlist (leave empty for default):

# Output will list all discovered subdomains:
Testing 75 potential subdomains...
Found valid subdomain: www.example.com
Found valid subdomain: mail.example.com

Subdomains found:
Number of subdomains found: 2
mail.example.com
www.example.com
```

3. Subdomain Enumeration (Gobuster-like):
```bash
# Basic usage with required arguments
python subdomainenum.py -d example.com -w /path/to/wordlist.txt

# With additional options
python subdomainenum.py -d example.com -w default_subdomains.txt -t 20 -v

# Output will show only valid subdomains:
www.example.com
mail.example.com
admin.example.com
```

4. Full Website Crawling with Subdomain Enumeration:
```bash
python ReconSpider/ReconSpider.py https://example.com --enum-subdomains --wordlist /path/to/wordlist.txt
```

### Troubleshooting

Common Issues:

1. Connection Errors
```
Error: Unable to resolve hostname to IP address
Solution: 
- Verify internet connectivity
- Check if the URL is correctly formatted
- Ensure DNS resolution is working properly
```

2. SSL Certificate Errors
```
Error: SSL Certificate Verification Failed
Solution:
- Update your Python packages: pip install --upgrade requests urllib3
- Verify the target site's SSL certificate is valid
```

3. Crawler Issues
```
Error: Spider not crawling all pages
Solutions:
- Check robots.txt restrictions
- Verify domain is correctly specified
- Enable debug logging:
  python ReconSpider/ReconSpider.py --loglevel=DEBUG https://example.com
```

4. Subdomain Enumeration Issues
```
Error: No subdomains found or slow enumeration
Solutions:
- Try a larger wordlist
- Adjust thread count with -t option
- Verify DNS resolution is working properly
- Use verbose mode (-v) to see progress
```

## Data Flow
ReconSpider processes websites through multiple analysis stages, from initial reconnaissance to detailed crawling and security analysis.

```ascii
URL Input → DNS Resolution → Security Headers Check → CORS Analysis
     ↓                                                    ↓
Subdomain Discovery ←---------------------------→ Web Crawling
     ↓                                                    ↓
Certificate Analysis                              Asset Discovery
     ↓                                                    ↓
     └----------------→ JSON Results ←--------------------┘
```

Component Interactions:
1. recon.py performs initial security analysis and DNS resolution
2. header.py analyzes HTTP response headers for security configuration
3. crt.py queries certificate transparency logs or uses wordlists for subdomain enumeration
4. subdomainenum.py provides dedicated Gobuster-like subdomain enumeration with concurrency
5. ReconSpider.py crawls the website to discover assets and security issues
6. All components write findings to results.json in a structured format
7. Each module can operate independently or as part of the complete workflow
8. Data is shared between components through file system and memory




