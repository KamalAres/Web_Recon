# Web_Recon - Comprehensive Web Reconnaissance and Security Assessment Tool

Web_Recon is a feature-rich external reconnaissance tool that performs automated security assessments and information gathering for web applications. It combines advanced subdomain enumeration, port scanning, technology fingerprinting, security checks, and website crawling into a unified workflow that helps security professionals and penetration testers gather actionable intelligence about target domains.

The tool provides comprehensive reconnaissance capabilities including subdomain discovery through multiple methods (wordlists and certificate transparency logs), port scanning with service detection, technology stack identification, security header analysis, CORS configuration checks, and website crawling for site mapping. Results are aggregated into detailed reports and visualizations to help identify potential security issues and attack surfaces.

## Repository Structure
```
.
├── create_modules.py         # Python script to initialize module structure (Windows compatible)
├── crt.py                    # Certificate transparency log integration
├── default_subdomains.txt    # Default wordlist for subdomain enumeration
├── header.py                 # HTTP header analysis functionality
├── main.py                   # Primary entry point and orchestration
├── recon.py                 # Core reconnaissance functionality
├── web_crawler.py           # Website crawler implementation
├── requirements.txt         # Python package dependencies
├── results.json            # Output file for scan results
├── subdomainenum.py        # Subdomain enumeration module
└── test_subdomainenum.py   # Unit tests for subdomain enumeration
```

## Usage Instructions
### Prerequisites
- Python 3.6+
- pip package manager
- nmap for port scanning functionality
- Required system packages for PDF report generation

### Installation
```bash
# Create virtual environment (recommended)
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Unix/Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Basic scan of a domain
python main.py -d example.com

# Full scan with all features enabled
python main.py -d example.com --report-format html pdf -t 20 --verbose
```

### More Detailed Examples
```python
# Subdomain enumeration only
python subdomainenum.py -d example.com -w wordlists/subdomains.txt

# Security header analysis
python header.py
> Enter website URL: https://example.com

# Web crawling only
python web_crawler.py -d example.com --max-pages 200 --max-depth 4 -o crawl_results.json

# Full reconnaissance with custom configuration
python main.py -d example.com \
    --output-dir ./results \
    --threads 30 \
    --ports 80,443,8080 \
    --max-pages 150 \
    --max-depth 3 \
    --report-format html \
    --verbose
```


## Data Flow
Web_Recon follows a modular data collection and analysis pipeline that processes target domains through multiple reconnaissance stages.

```ascii
Input Domain → Subdomain Discovery → Port Scanning → Tech Stack Analysis → Web Crawling → Security Checks → Report Generation
     ↓               ↓                    ↓               ↓                    ↓               ↓                ↓
[example.com] → [subdomains.txt] → [open ports/services] → [technologies] → [site map] → [vulnerabilities] → [report.html]
```

Component Interactions:
1. Main orchestrator (main.py) coordinates all scanning modules
2. Subdomain enumerator queries multiple sources (wordlists, CT logs)
3. Port scanner performs service detection on discovered hosts
4. Technology fingerprinter identifies web technologies and frameworks
5. Web crawler maps site structure and discovers resources
6. Security checker analyzes headers and common misconfigurations
7. Report generator consolidates findings into structured formats
8. Results are stored in JSON format for further processing
9. Visualization module creates relationship graphs of findings