import sys
import subprocess
import time
import os

def safe_sql_test(url):
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
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SQL injection test timed out for {url}")
        return "Test timed out"
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SQL injection test failed for {url}: {e}")
        return f"Test failed: {e}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 sql_injection_test.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    result = safe_sql_test(url)
    print(result)
