# Enterprise VAPT 

**Professional vulnerability assessment and penetration testing platform built for security professionals**



## Overview

Enterprise VAPT is a comprehensive vulnerability assessment and penetration testing platform designed for security professionals. Built with modern web technologies, it provides an intuitive GUI interface for conducting thorough security assessments without requiring command-line expertise.

## Key Features

### Core Capabilities
- **Ultra-Fast Scanning**: Advanced parallel scanning with RustScan and Nmap integration
- **Multi-Target Support**: Concurrent scanning of up to 500 targets simultaneously
- **Comprehensive Detection**: 20+ security tools integration for maximum coverage
- **Real-Time Dashboard**: Modern React interface with live progress tracking
- **Advanced Reporting**: Detailed PDF/JSON reports with risk categorization
- **REST API**: Complete API access for automation and integration

### Security Testing
- **Port Discovery**: Ultra-fast 1-65535 port scanning with RustScan and Nmap
- **Service Detection**: Version enumeration and fingerprinting
- **Vulnerability Assessment**: 1000+ vulnerability templates via Nuclei
- **Exploit Testing**: Advanced exploit validation for critical vulnerabilities
- **Web Application Testing**: XSS, SQLi, LFI, RFI detection
- **Network Analysis**: SMB, SSH, FTP security assessment

### Professional Interface
- **Dark/Light Mode**: Toggle between professional themes
- **Responsive Design**: Mobile-friendly dashboard
- **Real-Time Updates**: Live scan progress and log streaming
- **Data Visualization**: Interactive charts and progress indicators
- **Export Options**: PDF and JSON report generation

## Architecture

### Tech Stack

**Frontend (Vite React)**
- React 18 with functional components and hooks
- Vite for lightning-fast build and development
- Tailwind CSS for utility-first styling
- Lucide React for professional icons
- jsPDF for client-side PDF generation
- Axios for HTTP client communication

**Backend (Python FastAPI)**
- FastAPI for modern, fast Python web framework
- Uvicorn ASGI server for production performance
- AsyncIO for asynchronous processing
- Pydantic for data validation and serialization
- ThreadPoolExecutor for concurrent scan execution

**Security Tools**
- RustScan for ultra-fast port scanning
- Nmap for network discovery and security auditing
- Nuclei for vulnerability scanning with 1000+ templates
- Nikto for web server vulnerability scanning
- SQLMap for SQL injection testing
- WhatWeb for web application fingerprinting

## System Requirements

- **Python 3.8+**
- **Node.js 16+**
- **Linux/Unix environment** (Ubuntu 20.04+ recommended)
- **Minimum 4GB RAM** (8GB+ for bulk scanning)
- **Network access** to target systems

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/AkashRavindran2005/Vapt-dashboard.git
cd enterprise-vapt
```

### 2. Install Security Tools
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install core tools
sudo apt install -y nmap nikto whatweb python3-pip nodejs npm

# Install RustScan
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb

# Install Go-based tools
sudo apt install -y golang-go
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install SQLMap
sudo apt install -y sqlmap
```

### 3. Backend Setup
```bash
# Install Python dependencies
cd backend
pip3 install -r requirements.txt
```

### 4. Frontend Setup
```bash
# Install Node.js dependencies
cd client
npm install
```

## Quick Start

### Start the Application

**Terminal 1 - Backend API:**
```bash
cd backend
python3 enterprise_api.py
```

**Terminal 2 - Frontend Dashboard:**
```bash
cd client
npm run dev
```

### Access the Platform

- **Dashboard**: http://localhost:5173
- **API Server**: http://localhost:4000
- **API Documentation**: http://localhost:4000/docs

## Configuration

### Backend Configuration

Edit `enterprise_api.py` for server settings:
```python
# Server Configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4000

# CORS Settings
CORS_ORIGINS = [
    "http://localhost:5173",  # Vite dev server
    "http://localhost:3000",  # Alternative React dev server
]

# Job Limits
MAX_CONCURRENT_JOBS = 500
MAX_BULK_TARGETS = 1000
```

### Scanner Configuration

Edit `optimized_scan.py` for scanning parameters:
```python
# Thread Pool Configuration
THREAD_POOL = ThreadPoolExecutor(max_workers=200)

# Port Scanning Ranges
PORT_RANGES = [
    "1-1000",      # Common ports
    "1001-5000",   # Extended range
    "5001-10000",  # High ports
    "10001-65535"  # Very high ports
]

# Nuclei Configuration
NUCLEI_PARAMS = {
    'rate_limit': 100,
    'concurrency': 25,
    'bulk_size': 50,
    'retries': 1
}
```

### Frontend Configuration

Create `.env` file for environment variables:
```bash
# API Configuration
VITE_API_BASE_URL=http://localhost:4000
VITE_API_TIMEOUT=30000

# Feature Flags
VITE_ENABLE_DARK_MODE=true
VITE_ENABLE_EXPORT=true
VITE_ENABLE_EXPLOITS=true

# Refresh Intervals (milliseconds)
VITE_REFRESH_INTERVAL=2000
VITE_LOG_REFRESH_INTERVAL=1000
```

## Scanning Methodology

### Process Flow

1. **Target Validation**: DNS resolution and connectivity testing
2. **Port Discovery**: RustScan for initial discovery, Nmap for validation
3. **Service Detection**: Version enumeration and fingerprinting
4. **Vulnerability Assessment**: Multi-tool scanning with Nuclei, Nikto
5. **Exploit Testing**: Optional advanced exploit validation
6. **Risk Assessment**: Automated vulnerability categorization
7. **Report Generation**: Comprehensive results with remediation guidance

### Integrated Tools

| Tool | Purpose | Features |
|------|---------|----------|
| **RustScan** | Port Discovery | Ultra-fast 1-65535 scanning |
| **Nmap** | Service Detection | Version enumeration, script scanning |
| **Nuclei** | Vulnerability Scanner | 1000+ templates, CVE detection |
| **Nikto** | Web Scanner | Web server vulnerability assessment |
| **SQLMap** | SQL Injection | Database vulnerability testing |
| **WhatWeb** | Web Fingerprinting | Technology detection |
| **HTTPx** | HTTP Toolkit | Web service probing |

## Dashboard Features

### Scan Management
- **Single Target Scanning**: Individual target assessment
- **Bulk Scanning**: Multiple target processing with progress tracking
- **Job Queue Management**: Real-time status monitoring
- **Results Visualization**: Interactive charts and data displays

### Real-Time Monitoring
- **Live Progress**: Real-time scan progress bars
- **Log Streaming**: Backend scanner logs in real-time
- **Status Updates**: Instant job status changes
- **Performance Metrics**: Scan timing and statistics

### Reporting and Analytics
- **Risk Assessment**: Automated vulnerability categorization
- **Export Options**: PDF and JSON report generation
- **Search and Filter**: Advanced result filtering capabilities
- **Historical Data**: Scan history and trend analysis

## Usage Examples

### Single Target Scan
```bash
curl -X POST "http://localhost:4000/api/scan?target=example.com&enable_exploits=false"
```

### Bulk Scanning
```bash
curl -X POST "http://localhost:4000/api/bulk-scan" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com", "testphp.vulnweb.com"],
    "max_concurrent": 50,
    "enable_exploits": false
  }'
```

### Monitor Progress
```bash
curl "http://localhost:4000/api/scan/{job_id}"
curl "http://localhost:4000/api/logs"
```

## Security Considerations

### Ethical Use
This platform is designed for **authorized security testing only**. Users must:
- Obtain proper written authorization before scanning any systems
- Comply with applicable laws and regulations
- Use the platform responsibly and ethically
- Respect rate limits and avoid DoS conditions

### Network Security
- Deploy in isolated/segmented networks for testing
- Use appropriate firewall configurations
- Monitor all scanning activities
- Implement proper access controls

### Data Protection
- Sanitize sensitive information from reports
- Implement secure data storage practices
- Follow organizational data retention policies
- Ensure secure handling of scan results

## Development

### Project Structure
```
enterprise-vapt/
├── client/               # Vite React frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   └── Dashboard.jsx   # Main dashboard
│   ├── package.json
│   └── vite.config.js
├── backend/                # Python FastAPI backend
   |__ scripts/ 
   ├── enterprise_api.py   # FastAPI server
   ├── optimized_scan.py   # Scanner engine
   └── requirements.txt
```

### Development Setup
```bash
# Backend development with hot reload
uvicorn enterprise_api:app --reload --host 0.0.0.0 --port 4000

# Frontend development with Vite
npm run dev
```

## Disclaimer

**Important**: This tool is for **authorized security testing only**.

- Users are responsible for ensuring proper authorization
- Unauthorized scanning is illegal and unethical
- The developers are not responsible for misuse
- Always comply with local laws and regulations
