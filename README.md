# ReconSpider: Comprehensive Web Reconnaissance and Security Analysis Tool

ReconSpider is a powerful Python-based web reconnaissance tool that combines web crawling, security header analysis, and domain intelligence gathering capabilities. It helps security professionals and developers assess website security posture, discover potential vulnerabilities, and gather comprehensive information about web applications.

The tool provides automated scanning of websites to extract valuable information including security headers, CORS configurations, subdomains, and various web assets while performing security checks. ReconSpider features intelligent crawling that respects domain boundaries, comprehensive header analysis, and detailed reporting of findings in structured JSON format.

## Repository Structure
```
.
├── crt.py                  # Certificate transparency log scanner for subdomain enumeration
├── header.py              # HTTP header analyzer for security assessment
├── recon.py              # Core security header and CORS analysis functionality
├── ReconSpider/          # Main web crawler implementation directory
│   └── ReconSpider.py    # Scrapy-based intelligent web crawler
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

3. Discover subdomains:
```bash
python crt.py
# Enter hostname when prompted
```

4. Full website crawling and analysis:
```bash
python ReconSpider/ReconSpider.py https://example.com
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

2. Subdomain Discovery:
```python
python crt.py
Enter hostname: example.com

# Output will list all discovered subdomains:
Subdomains found:
blog.example.com
dev.example.com
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
3. crt.py queries certificate transparency logs for subdomain enumeration
4. ReconSpider.py crawls the website to discover assets and security issues
5. All components write findings to results.json in a structured format
6. Each module can operate independently or as part of the complete workflow
7. Data is shared between components through file system and memory