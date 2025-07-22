import asyncio
import subprocess
import json
import time
import logging
import re
import socket
import requests
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import os
import tempfile
import shutil
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

THREAD_POOL = ThreadPoolExecutor(max_workers=200)
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), 'scripts')

def check_tool_availability():
    required_tools = ['nmap', 'rustscan', 'nuclei', 'nikto', 'whatweb', 'httpx', 'sqlmap']
    available_tools = {}
    
    for tool in required_tools:
        tool_path = shutil.which(tool)
        available_tools[tool] = tool_path is not None
        if tool_path:
            logger.info(f"Tool {tool} found at: {tool_path}")
        else:
            logger.warning(f"Tool {tool} not found in PATH")
    
    return available_tools

async def run_command_ultra_fast(cmd: str) -> Tuple[str, str, int]:
    try:
        logger.info(f"Executing command: {cmd}")
        
        if isinstance(cmd, str):
            cmd_parts = cmd.split()
        else:
            cmd_parts = cmd

        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=500*1024*1024
        )

        stdout, stderr = await process.communicate()
        stdout_str = stdout.decode('utf-8', errors='ignore') if stdout else ""
        stderr_str = stderr.decode('utf-8', errors='ignore') if stderr else ""
        returncode = process.returncode or 0

        logger.info(f"Command completed: {cmd_parts[0]} - Return code: {returncode}")
        logger.info(f"Output length: {len(stdout_str)} characters")
        
        return (stdout_str, stderr_str, returncode)
    except Exception as e:
        logger.error(f"Command execution failed: {cmd} - {str(e)}")
        return "", str(e), 1

async def ultra_fast_port_discovery(target: str) -> List[int]:
    logger.info(f"Starting port discovery for target: {target}")
    
    try:
        socket.gethostbyname(target)
        logger.info(f"Target {target} is resolvable")
    except socket.gaierror:
        logger.error(f"Cannot resolve target: {target}")
        return []

    all_ports = set()

    logger.info("Method 1: RustScan port discovery")
    if shutil.which('rustscan'):
        cmd = f"rustscan -a {target} --range 1-65535 --batch-size 10000 --ulimit 10000"
        stdout, stderr, returncode = await run_command_ultra_fast(cmd)
        
        if returncode == 0 and stdout:
            for line in stdout.split('\n'):
                if 'Open' in line or '->' in line or 'Discovered' in line:
                    port_patterns = [
                        r'(\d+)/tcp',
                        r'port (\d+)',
                        r':(\d+)\s+open',
                        r'(\d+)\s+open'
                    ]
                    for pattern in port_patterns:
                        port_matches = re.findall(pattern, line)
                        for port_str in port_matches:
                            try:
                                port = int(port_str)
                                if 1 <= port <= 65535:
                                    all_ports.add(port)
                                    logger.info(f"RustScan discovered port: {port}")
                            except:
                                continue

    if len(all_ports) < 10:
        logger.info("Method 2: Parallel Nmap comprehensive scan")
        
        port_ranges = [
            "1-1000",
            "1001-5000",
            "5001-10000",
            "10001-20000",
            "20001-30000",
            "30001-40000",
            "40001-50000",
            "50001-65535"
        ]

        async def scan_range(port_range):
            cmd = f"nmap -sS -p{port_range} --open {target} -T5 --min-rate=10000 --max-retries=1"
            stdout, stderr, returncode = await run_command_ultra_fast(cmd)
            range_ports = set()
            if returncode == 0 and stdout:
                for line in stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        try:
                            port = int(line.split('/')[0].strip())
                            range_ports.add(port)
                            logger.info(f"Nmap range scan found port: {port}")
                        except:
                            continue
            return range_ports

        range_tasks = [scan_range(port_range) for port_range in port_ranges]
        range_results = await asyncio.gather(*range_tasks, return_exceptions=True)

        for result in range_results:
            if isinstance(result, set):
                all_ports.update(result)

    final_ports = sorted(list(all_ports))
    logger.info(f"Port discovery completed: {len(final_ports)} ports found")
    logger.info(f"Discovered ports: {final_ports}")
    return final_ports

async def ultra_fast_service_detection(target: str, ports: List[int]) -> Dict[int, Dict[str, str]]:
    logger.info(f"Starting service detection for target: {target}")
    services = {}
    
    if not ports or not shutil.which('nmap'):
        return services

    chunk_size = 50
    port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]

    async def scan_chunk(port_chunk):
        port_list = ','.join(map(str, port_chunk))
        cmd = f"nmap -sV -sC -p {port_list} {target} --version-intensity 3 -T5 --min-rate=10000 --max-retries=1"
        stdout, stderr, returncode = await run_command_ultra_fast(cmd)
        
        if not stdout or returncode != 0:
            return {}

        chunk_services = {}
        lines = stdout.split('\n')
        current_port = None
        current_service = {}
        scripts = []

        for line in lines:
            line = line.strip()
            if '/tcp' in line and 'open' in line:
                if current_port and current_service:
                    if scripts:
                        current_service['scripts'] = scripts[:]
                    chunk_services[current_port] = current_service.copy()

                try:
                    parts = line.split()
                    port_str = parts[0].split('/')[0]
                    current_port = int(port_str)
                    service_name = parts[2] if len(parts) > 2 else 'unknown'
                    version_info = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'

                    current_service = {
                        'service': service_name,
                        'version': version_info
                    }
                    scripts = []
                except (ValueError, IndexError):
                    continue

            elif line.startswith('|') and current_port:
                script_line = line[1:].strip()
                if script_line:
                    scripts.append(script_line)

        if current_port and current_service:
            if scripts:
                current_service['scripts'] = scripts
            chunk_services[current_port] = current_service

        return chunk_services

    tasks = [scan_chunk(chunk) for chunk in port_chunks]
    chunk_results = await asyncio.gather(*tasks, return_exceptions=True)

    for chunk_result in chunk_results:
        if isinstance(chunk_result, dict):
            services.update(chunk_result)

    logger.info(f"Service detection completed: {len(services)} services identified")
    return services

SCRIPT_SET = {
    21: "ftp-anon,ftp-vsftpd-backdoor,ftp-bounce",
    22: "ssh-auth-methods,ssh-hostkey,ssh-run,ssh2-enum-algos",
    23: "telnet-encryption,telnet-ntlm-info",
    25: "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344",
    53: "dns-zone-transfer,dns-recursion,dns-cache-snoop",
    80: "http-vuln*,http-enum,http-dombased-xss,http-sql-injection,http-slowloris-check",
    135: "msrpc-enum,rpc-grind",
    139: "smb-vuln*,smb-enum-shares,smb-enum-users",
    443: "http-vuln*,http-enum,ssl-dh-params,ssl-heartbleed,ssl-poodle,ssl-ccs-injection",
    445: "smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery",
    993: "ssl-enum-ciphers,ssl-cert,ssl-date",
    995: "ssl-enum-ciphers,ssl-cert,ssl-date",
    1433: "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell",
    3306: "mysql-info,mysql-empty-password,mysql-users,mysql-databases",
    3389: "rdp-enum-encryption,rdp-vuln-ms12-020",
    5432: "pgsql-brute,postgres-version",
    8080: "http-vuln*,http-enum,http-title",
    8443: "http-vuln*,http-enum,ssl-heartbleed",
    8180: "http-vuln*,http-enum,http-title"
}

async def run_nmap_vulns_ultra_fast(target: str, ports: List[int]) -> List[str]:
    logger.info(f"Starting nmap vulnerability scan for target: {target}")
    vulns = []
    
    if not shutil.which("nmap"):
        return vulns

    async def scan_port_vulns(port):
        scripts = SCRIPT_SET.get(port)
        if not scripts:
            return []

        cmd = f"nmap -p{port} --script {scripts} -T5 --min-rate=10000 --max-retries=1 {target}"
        stdout, stderr, returncode = await run_command_ultra_fast(cmd)

        port_vulns = []
        for line in stdout.splitlines():
            if "|_" in line or "| " in line:
                text = line.strip("|_ ").strip()
                if text and "not vuln" not in text.lower():
                    port_vulns.append(f"{port}/tcp: {text}")
        return port_vulns

    tasks = [scan_port_vulns(port) for port in ports if port in SCRIPT_SET]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            vulns.extend(result)

    if not vulns:
        vulns.append("NMAP-INFO: No vulnerable scripts triggered on scanned ports")

    logger.info(f"Nmap vulnerability scan completed: {len(vulns)} findings")
    return vulns

async def run_nuclei_fixed_ultra_fast(target: str, ports: List[int]) -> List[str]:
    logger.info(f"Starting nuclei scan for target: {target}")
    findings = []
    
    if not shutil.which("nuclei"):
        logger.warning("nuclei not installed")
        return findings

    logger.info("Updating nuclei templates")
    await run_command_ultra_fast("nuclei -update-templates")

    urls = []
    web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 8180, 9000, 9001, 9002)]
    
    for port in web_ports:
        proto = "https" if port in (443, 8443) else "http"
        base_url = f"{proto}://{target}:{port}"
        
        urls.extend([
            base_url,
            f"{base_url}/",
            f"{base_url}/index.html",
            f"{base_url}/index.php",
            f"{base_url}/admin/",
            f"{base_url}/login/",
            f"{base_url}/api/",
            f"{base_url}/dvwa/",
            f"{base_url}/dvwa/login.php",
            f"{base_url}/mutillidae/",
            f"{base_url}/mutillidae/index.php",
            f"{base_url}/phpMyAdmin/",
            f"{base_url}/phpMyAdmin/index.php",
            f"{base_url}/twiki/",
            f"{base_url}/dav/",
            f"{base_url}/tikiwiki/",
            f"{base_url}/test/",
            f"{base_url}/backup/",
            f"{base_url}/config/",
            f"{base_url}/uploads/"
        ])

    if not urls:
        logger.warning("No web URLs found for nuclei scan")
        return findings

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("\n".join(urls))
        url_file = f.name

    cmd = (
        f"nuclei -l {url_file} "
        "-rate-limit 100 -c 25 -bulk-size 50 "
        "-severity info,low,medium,high,critical "
        "-tags cve,oast,tech,default-logins,exposures,misconfig,sqli,xss,lfi,rfi,rce,ssrf "
        "-jsonl "
        "-no-color "
        "-silent "
        "-include-rr "
        "-stats "
        "-retries 1 "
        "-no-update-templates"
    )

    logger.info(f"Running nuclei scan: {cmd}")
    stdout, stderr, returncode = await run_command_ultra_fast(cmd)
    os.unlink(url_file)

    logger.info(f"Nuclei output length: {len(stdout)} characters")
    if stderr:
        logger.info(f"Nuclei stderr: {stderr[:300]}...")

    if stdout.strip():
        for line_num, line in enumerate(stdout.strip().splitlines(), 1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                severity = info.get("severity", "info").upper()
                name = info.get("name", "Unknown")
                description = info.get("description", "")
                template_id = obj.get("template-id", "unknown")
                template_path = obj.get("template-path", "")
                matched_at = obj.get("matched-at", obj.get("host", ""))

                finding_parts = [
                    f"NUCLEI-{severity}",
                    f"{name}",
                    f"({template_id})"
                ]

                if description:
                    finding_parts.append(f"- {description[:100]}...")

                finding_parts.append(f"=> {matched_at}")
                finding = ": ".join(finding_parts[:2]) + " " + " ".join(finding_parts[2:])
                findings.append(finding)

                logger.info(f"Nuclei finding: {severity} - {name} on {matched_at}")

            except json.JSONDecodeError as e:
                if any(keyword in line.lower() for keyword in
                       ['vulnerable', 'exposed', 'misconfigured', 'detected', 'found']):
                    findings.append(f"NUCLEI-INFO: {line}")
                logger.debug(f"Non-JSON nuclei output (line {line_num}): {line[:100]}...")
                continue
            except Exception as e:
                logger.debug(f"Failed to parse nuclei line {line_num}: {line[:50]} - {e}")
                continue

    if not findings:
        logger.info("Running enhanced nuclei fallback test")
        basic_cmd = f"nuclei -u http://{target} -tags tech -silent -jsonl"
        basic_stdout, basic_stderr, basic_rc = await run_command_ultra_fast(basic_cmd)
        
        if basic_stdout:
            for line in basic_stdout.strip().splitlines():
                try:
                    obj = json.loads(line)
                    name = obj.get("info", {}).get("name", "Technology Detection")
                    template_id = obj.get("template-id", "tech")
                    findings.append(f"NUCLEI-TECH: {name} ({template_id}) => http://{target}")
                except:
                    continue

    if not findings:
        findings.append("NUCLEI-INFO: Scan completed successfully, no vulnerabilities detected with current templates")
    else:
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'TECH': 5}
        findings.sort(key=lambda x: severity_order.get(x.split('-')[1].split(':')[0], 6))

    logger.info(f"Nuclei scan completed: {len(findings)} findings")
    return findings

async def run_nikto_ultra_fast(target: str, ports: List[int]) -> List[str]:
    logger.info(f"Starting nikto scan for target: {target}")
    findings = []
    
    if not shutil.which('nikto'):
        logger.error("Nikto not available")
        return findings

    web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8180, 9000]]
    if not web_ports:
        logger.warning("No web ports found for nikto scan")
        return findings

    async def scan_port(port):
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{target}:{port}"

        cmd = [
            'nikto',
            '-h', url,
            '-nointeractive',
            '-ask', 'no',
            '-Display', 'V',
            '-maxtime', '30s'
        ]

        logger.info(f"Running nikto on {url}")
        stdout, stderr, returncode = await run_command_ultra_fast(' '.join(cmd))

        port_findings = []
        if stdout:
            logger.info(f"Nikto output for port {port}: {len(stdout)} characters")
            
            for line in stdout.split('\n'):
                line = line.strip()
                if (line.startswith('+') or
                    any(keyword in line.lower() for keyword in
                        ['vulnerable', 'outdated', 'exposed', 'cgi-bin', 'admin',
                         'backup', 'config', 'server:', 'osvdb', 'cve-', 'directory'])):
                    
                    finding = line.replace('+', '').strip()
                    if finding and len(finding) > 10:
                        port_findings.append(f"NIKTO-{port}: {finding}")
                        logger.info(f"Nikto finding: {finding[:80]}...")

        if not port_findings:
            port_findings.append(f"NIKTO-{port}: Scan completed, no significant findings")

        return port_findings

    tasks = [scan_port(port) for port in web_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    logger.info(f"Nikto scan completed: {len(findings)} findings")
    return findings

async def run_whatweb_ultra_fast(target: str, ports: List[int]) -> List[str]:
    logger.info(f"Starting whatweb scan for target: {target}")
    technologies = []
    
    if not shutil.which('whatweb'):
        logger.error("WhatWeb not available")
        return technologies

    web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8180, 9000]]
    if not web_ports:
        logger.warning("No web ports found for whatweb scan")
        return technologies

    async def scan_port(port):
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{target}:{port}"

        cmd = f"whatweb {url} --aggression=3 --max-threads=100"
        stdout, stderr, returncode = await run_command_ultra_fast(cmd)

        port_techs = []
        for line in stdout.split('\n'):
            if target in line and '[' in line:
                tech_matches = re.findall(r'\[([^\]]+)\]', line)
                for tech in tech_matches:
                    if tech and len(tech) > 2:
                        port_techs.append(f"WHATWEB-{port}: {tech}")
        return port_techs

    tasks = [scan_port(port) for port in web_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            technologies.extend(result)

    logger.info(f"WhatWeb scan completed: {len(technologies)} technologies found")
    return technologies

async def run_path_discovery_ultra_fast(target: str, ports: List[int]) -> List[str]:
    logger.info(f"Starting path discovery for target: {target}")
    paths = []
    
    web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8180, 9000]]
    if not web_ports:
        logger.warning("No web ports found for path discovery")
        return paths

    common_paths = [
        '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
        '/backup', '/config', '/test', '/api', '/robots.txt', '/sitemap.xml',
        '/.git', '/.svn', '/uploads', '/files', '/images', '/css', '/js',
        '/dvwa', '/mutillidae', '/phpMyAdmin', '/dav', '/cgi-bin',
        '/tikiwiki', '/tikiwiki-old', '/twiki', '/phpinfo.php', '/info.php',
        '/dashboard', '/panel', '/control', '/manage', '/system', '/status',
        '/tmp', '/var', '/etc', '/proc', '/home', '/root', '/usr'
    ]

    async def scan_port_paths(port):
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{target}:{port}"
        port_paths = []

        async def check_path(path):
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    THREAD_POOL,
                    lambda: requests.get(f"{base_url}{path}", timeout=3, allow_redirects=False)
                )

                if response.status_code in [200, 301, 302, 403]:
                    return f"PATH-{port}: {path} (Status: {response.status_code})"
            except:
                pass
            return None

        batch_size = 20
        for i in range(0, len(common_paths), batch_size):
            batch = common_paths[i:i + batch_size]
            tasks = [check_path(path) for path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result and isinstance(result, str):
                    port_paths.append(result)

        return port_paths

    tasks = [scan_port_paths(port) for port in web_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            paths.extend(result)

    logger.info(f"Path discovery completed: {len(paths)} paths found")
    return paths

async def run_httpx_ultra_fast(target: str, ports: List[int]) -> Dict:
    logger.info(f"Starting httpx scan for target: {target}")
    data = {}
    
    if not shutil.which("httpx"):
        logger.warning("httpx not in PATH")
        return data

    web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 8180, 9000)]
    if not web_ports:
        logger.info("No web ports found for httpx scan")
        return data

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        for port in web_ports:
            proto = "https" if port in (443, 8443) else "http"
            f.write(f"{proto}://{target}:{port}\n")
        url_file = f.name

    cmd = (
        f"httpx -l {url_file} "
        "-jsonl -title -tech-detect -server "
        "-status-code -content-length -no-fallback "
        "-threads 200 -rate-limit 2000"
    )

    stdout, stderr, returncode = await run_command_ultra_fast(cmd)
    os.unlink(url_file)

    for line in stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            port = urlparse(obj["url"]).port or (443 if obj["url"].startswith("https") else 80)
            data[f"port_{port}"] = obj
        except Exception as e:
            logger.debug(f"Bad line ignored: {line[:60]} ({e})")

    if not data:
        for port in web_ports:
            data[f"port_{port}"] = {"url": f"{target}:{port}", "error": "httpx produced no output"}

    logger.info(f"HTTPX scan completed: {len(data)} services analyzed")
    return data

async def run_custom_checks_ultra_fast(target: str, ports: List[int], services: Dict[int, Dict[str, str]]) -> List[str]:
    logger.info(f"Starting custom checks for target: {target}")
    checks = []

    critical_checks = {
        21: "HIGH: FTP service detected - potential anonymous access",
        22: "MEDIUM: SSH service detected - brute force target",
        23: "CRITICAL: Telnet service detected - unencrypted protocol",
        25: "MEDIUM: SMTP service detected - mail relay risk",
        53: "LOW: DNS service detected - information disclosure",
        80: "INFO: HTTP service detected - web application present",
        135: "HIGH: RPC service detected - Windows enumeration risk",
        139: "MEDIUM: NetBIOS service detected - information disclosure",
        443: "INFO: HTTPS service detected - encrypted web application",
        445: "CRITICAL: SMB service detected - EternalBlue risk",
        993: "LOW: IMAPS service detected - encrypted email",
        995: "LOW: POP3S service detected - encrypted email",
        1433: "HIGH: MS SQL Server detected - database exposure",
        3306: "HIGH: MySQL detected - database exposure",
        3389: "CRITICAL: RDP service detected - remote access risk",
        5432: "HIGH: PostgreSQL detected - database exposure",
        8080: "MEDIUM: HTTP-Alt service detected - web application",
        8180: "MEDIUM: HTTP-Alt service detected - web application",
        8443: "MEDIUM: HTTPS-Alt service detected - web application"
    }

    for port in ports:
        if port in critical_checks:
            checks.append(critical_checks[port])

    for port, service_info in services.items():
        service_name = service_info.get('service', '').lower()
        version = service_info.get('version', '').lower()

        if 'ftp' in service_name:
            if 'vsftpd 2.3.4' in version:
                checks.append("CRITICAL: vsftpd 2.3.4 backdoor vulnerability detected")
            if 'anonymous' in str(service_info.get('scripts', [])):
                checks.append("HIGH: FTP anonymous access enabled")

        if 'ssh' in service_name:
            if any(old in version for old in ['openssh 2.', 'openssh 3.', 'openssh 4.', 'openssh 5.']):
                checks.append("HIGH: Outdated SSH version with known vulnerabilities")

        if 'apache' in version:
            if any(old in version for old in ['2.0', '2.2']):
                checks.append("MEDIUM: Outdated Apache version detected")

        if 'nginx' in version:
            if any(old in version for old in ['1.0', '1.2', '1.4']):
                checks.append("MEDIUM: Outdated Nginx version detected")

        if 'mysql' in service_name:
            if any(old in version for old in ['5.0', '5.1', '5.5']):
                checks.append("HIGH: Outdated MySQL version with vulnerabilities")

        if 'microsoft-ds' in service_name or 'netbios' in service_name:
            checks.append("HIGH: SMB service exposed - potential EternalBlue target")

    logger.info(f"Custom checks completed: {len(checks)} issues found")
    return checks

async def run_eternalblue_check(target: str, port: int = 445) -> List[str]:
    logger.info(f"Starting EternalBlue check for {target}:{port}")
    results = []
    
    try:
        cmd = [
            "python3", "scripts/eternalblue_check.py",
            target, str(port)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if line.strip() and ('ETERNALBLUE' in line or 'MS17-010' in line):
                    results.append(line.strip())
        
        if result.stderr:
            logger.warning(f"EternalBlue check stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        results.append(f"ETERNALBLUE-TIMEOUT: {target}:{port} - Check timed out")
    except Exception as e:
        results.append(f"ETERNALBLUE-ERROR: {target}:{port} - {str(e)}")
    
    return results

async def run_ftp_exploit_check(target: str, port: int = 21) -> List[str]:
    logger.info(f"Starting FTP exploit check for {target}:{port}")
    results = []
    
    try:
        cmd = [
            "python3", "scripts/ftp_exploit_test.py",
            target, str(port)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if line.strip() and ('FTP-' in line):
                    results.append(line.strip())
        
        if result.stderr:
            logger.warning(f"FTP exploit check stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        results.append(f"FTP-EXPLOIT-TIMEOUT: {target}:{port} - Check timed out")
    except Exception as e:
        results.append(f"FTP-EXPLOIT-ERROR: {target}:{port} - {str(e)}")
    
    return results

async def run_ssh_exploit_check(target: str, port: int = 22) -> List[str]:
    logger.info(f"Starting SSH exploit check for {target}:{port}")
    results = []
    
    try:
        cmd = [
            "python3", "scripts/ssh_exploit_test.py",
            target, str(port)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if line.strip() and ('SSH-' in line):
                    results.append(line.strip())
        
        if result.stderr:
            logger.warning(f"SSH exploit check stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        results.append(f"SSH-EXPLOIT-TIMEOUT: {target}:{port} - Check timed out")
    except Exception as e:
        results.append(f"SSH-EXPLOIT-ERROR: {target}:{port} - {str(e)}")
    
    return results

async def run_sql_injection_check(target: str, port: int) -> List[str]:
    logger.info(f"Starting SQL injection check for {target}:{port}")
    results = []
    
    try:
        cmd = [
            "python3", "scripts/sql_injection_test.py",
            target, str(port)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if line.strip() and ('SQL-' in line):
                    results.append(line.strip())
        
        if result.stderr:
            logger.warning(f"SQL injection check stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        results.append(f"SQL-INJECTION-TIMEOUT: {target}:{port} - Check timed out")
    except Exception as e:
        results.append(f"SQL-INJECTION-ERROR: {target}:{port} - {str(e)}")
    
    return results

async def run_web_exploit_check(target: str, port: int) -> List[str]:
    logger.info(f"Starting web exploit check for {target}:{port}")
    results = []
    
    try:
        cmd = [
            "python3", "scripts/web_exploit_test.py",
            target, str(port)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if line.strip() and ('WEB-' in line):
                    results.append(line.strip())
        
        if result.stderr:
            logger.warning(f"Web exploit check stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        results.append(f"WEB-EXPLOIT-TIMEOUT: {target}:{port} - Check timed out")
    except Exception as e:
        results.append(f"WEB-EXPLOIT-ERROR: {target}:{port} - {str(e)}")
    
    return results

async def run_clean_exploits_ultra_fast(target: str, ports: List[int], services: Dict[int, Dict[str, str]]) -> Dict[str, List[str]]:
    logger.info(f"Starting clean exploit testing for target: {target}")
    
    exploit_results = {
        'eternalblue': [],
        'ftp_exploits': [],
        'ssh_exploits': [],
        'web_exploits': [],
        'rdp_exploits': [],
        'sql_injection': [],
        'warnings': []
    }

    tasks = []
    
    if 445 in ports:
        tasks.append(('eternalblue', run_eternalblue_check(target, 445)))
    
    if 21 in ports:
        tasks.append(('ftp_exploits', run_ftp_exploit_check(target, 21)))
    
    if 22 in ports:
        tasks.append(('ssh_exploits', run_ssh_exploit_check(target, 22)))
    
    web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8180]]
    if web_ports:
        for port in web_ports:
            tasks.append(('web_exploits', run_web_exploit_check(target, port)))
            tasks.append(('sql_injection', run_sql_injection_check(target, port)))

    results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
    
    for i, (category, result) in enumerate(zip([task[0] for task in tasks], results)):
        if isinstance(result, list):
            exploit_results[category].extend(result)
        elif isinstance(result, Exception):
            exploit_results['warnings'].append(f"Error in {category}: {str(result)}")

    logger.info(f"Clean exploit testing completed for target: {target}")
    return exploit_results

async def scan_single(target: str, enable_exploits: bool = False) -> Dict:
    start_time = time.time()
    
    logger.info(f"Starting comprehensive scan for target: {target}")
    
    try:
        tool_check = check_tool_availability()
        
        ports = await ultra_fast_port_discovery(target)
        
        if not ports:
            logger.warning(f"No open ports found for target: {target}")
            return {
                'target': target,
                'risk': 'Normal',
                'timestamp': time.time(),
                'scan_time': time.time() - start_time,
                'ports_masscan': [],
                'services': {},
                'total_vulnerabilities': 0,
                'nuclei': ['No vulnerabilities found - no open ports'],
                'nikto': ['No web services found'],
                'nmap_vulns': ['No services to test'],
                'custom_checks': ['No services detected'],
                'whatweb': ['No web services found'],
                'paths': ['No web services found'],
                'httpx': {},
                'error': 'No open ports detected'
            }

        services = await ultra_fast_service_detection(target, ports)
        
        tasks = [
            run_nmap_vulns_ultra_fast(target, ports),
            run_nuclei_fixed_ultra_fast(target, ports),
            run_nikto_ultra_fast(target, ports),
            run_whatweb_ultra_fast(target, ports),
            run_path_discovery_ultra_fast(target, ports),
            run_httpx_ultra_fast(target, ports),
            run_custom_checks_ultra_fast(target, ports, services)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        nmap_vulns = results[0] if isinstance(results[0], list) else []
        nuclei_results = results[1] if isinstance(results[1], list) else []
        nikto_results = results[2] if isinstance(results[2], list) else []
        whatweb_results = results[3] if isinstance(results[3], list) else []
        paths_results = results[4] if isinstance(results[4], list) else []
        httpx_results = results[5] if isinstance(results[5], dict) else {}
        custom_checks = results[6] if isinstance(results[6], list) else []

        exploit_results = None
        if enable_exploits:
            exploit_results = await run_clean_exploits_ultra_fast(target, ports, services)

        total_vulnerabilities = len(nmap_vulns) + len(nuclei_results) + len(nikto_results) + len(custom_checks)
        
        risk = 'Normal'
        if any('CRITICAL' in finding for finding in nmap_vulns + nuclei_results + nikto_results + custom_checks):
            risk = 'Critical'
        elif any('HIGH' in finding for finding in nmap_vulns + nuclei_results + nikto_results + custom_checks):
            risk = 'High'
        elif any('MEDIUM' in finding for finding in nmap_vulns + nuclei_results + nikto_results + custom_checks):
            risk = 'Medium'
        elif total_vulnerabilities > 0:
            risk = 'Low'

        result = {
            'target': target,
            'risk': risk,
            'timestamp': time.time(),
            'scan_time': time.time() - start_time,
            'ports_masscan': ports,
            'services': services,
            'total_vulnerabilities': total_vulnerabilities,
            'nuclei': nuclei_results,
            'nikto': nikto_results,
            'nmap_vulns': nmap_vulns,
            'custom_checks': custom_checks,
            'whatweb': whatweb_results,
            'paths': paths_results,
            'httpx': httpx_results
        }

        if exploit_results:
            result['exploit_results'] = exploit_results

        logger.info(f"Scan completed for target: {target} in {time.time() - start_time:.2f} seconds")
        return result

    except Exception as e:
        logger.error(f"Scan failed for target: {target} - {str(e)}")
        return {
            'target': target,
            'risk': 'Error',
            'timestamp': time.time(),
            'scan_time': time.time() - start_time,
            'ports_masscan': [],
            'services': {},
            'total_vulnerabilities': 0,
            'nuclei': [f'Scan error: {str(e)}'],
            'nikto': [f'Scan error: {str(e)}'],
            'nmap_vulns': [f'Scan error: {str(e)}'],
            'custom_checks': [f'Scan error: {str(e)}'],
            'whatweb': [f'Scan error: {str(e)}'],
            'paths': [f'Scan error: {str(e)}'],
            'httpx': {},
            'error': str(e)
        }

async def scan_bulk(targets: List[str], max_concurrent: int = 50, progress_callback=None, enable_exploits: bool = False) -> List[Dict]:
    logger.info(f"Starting bulk scan for {len(targets)} targets with max concurrency: {max_concurrent}")
    
    unique_targets = list(set(targets))
    deduplicated_count = len(targets) - len(unique_targets)
    
    if deduplicated_count > 0:
        logger.info(f"Removed {deduplicated_count} duplicate targets")
    
    semaphore = asyncio.Semaphore(max_concurrent)
    completed = 0
    results = []

    async def scan_target_with_semaphore(target):
        nonlocal completed
        async with semaphore:
            try:
                result = await scan_single(target, enable_exploits)
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(unique_targets))
                return result
            except Exception as e:
                logger.error(f"Error scanning target {target}: {str(e)}")
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(unique_targets))
                return {
                    'target': target,
                    'risk': 'Error',
                    'timestamp': time.time(),
                    'scan_time': 0,
                    'ports_masscan': [],
                    'services': {},
                    'total_vulnerabilities': 0,
                    'nuclei': [f'Scan error: {str(e)}'],
                    'nikto': [f'Scan error: {str(e)}'],
                    'nmap_vulns': [f'Scan error: {str(e)}'],
                    'custom_checks': [f'Scan error: {str(e)}'],
                    'whatweb': [f'Scan error: {str(e)}'],
                    'paths': [f'Scan error: {str(e)}'],
                    'httpx': {},
                    'error': str(e)
                }

    tasks = [scan_target_with_semaphore(target) for target in unique_targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_results = []
    for result in results:
        if isinstance(result, dict):
            valid_results.append(result)
        else:
            logger.error(f"Invalid result type: {type(result)}")

    logger.info(f"Bulk scan completed: {len(valid_results)} results generated")
    return valid_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 optimized_scan.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    result = asyncio.run(scan_single(target))
    print(json.dumps(result, indent=2))
