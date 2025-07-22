import sys
import subprocess
import time
import os

def safe_sql_test(target, port):
    protocol = "https" if port == "443" else "http"
    url = f"{protocol}://{target}:{port}"
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting SQL injection test for {url}")
    
    results_dir = "./results/"
    os.makedirs(results_dir, exist_ok=True)
    
    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--level=2",
        "--risk=1",
        "--crawl=2",
        "--threads=3",
        "--timeout=10",
        "--retries=1",
        "--technique=B",  
        "--no-cast",
        "--skip-urlencode",
        f"--output-dir={results_dir}",
        "--flush-session"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SQL injection test completed for {url}")
        
        stdout = result.stdout
        
        if "vulnerable" in stdout.lower() or "injection" in stdout.lower():
            print(f"SQL-INJECTION-VULNERABLE: {url} - SQL injection detected")
            print(f"SQL-INJECTION-DETAILS: Boolean-based blind SQL injection found")
            print(f"SQL-INJECTION-IMPACT: Database information disclosure possible")
            print(f"SQL-INJECTION-RECOMMENDATION: Implement parameterized queries")
        else:
            print(f"SQL-INJECTION-SAFE: {url} - No SQL injection vulnerabilities detected")
        
        return stdout
        
    except subprocess.TimeoutExpired:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SQL injection test timed out for {url}")
        return "Test timed out"
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SQL injection test failed for {url}: {e}")
        return f"Test failed: {e}"

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 sql_injection_test.py <target> <port>")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2]
    result = safe_sql_test(target, port)
    print(result)
