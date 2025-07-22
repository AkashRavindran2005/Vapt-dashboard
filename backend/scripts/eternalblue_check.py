import sys
import subprocess
import time
import os

def check_eternalblue(target, port=445):
    try:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting EternalBlue check for {target}")
        
        cmd = [
            "nmap",
            "-p", str(port),
            "--script", "smb-vuln-ms17-010",
            "--script-args", "vulns.showall",
            target
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] EternalBlue check completed for {target}")
        
        stdout = result.stdout
        
        if "VULNERABLE" in stdout and "ms17-010" in stdout:
            print(f"ETERNALBLUE-VULNERABLE: {target}:{port} - MS17-010 vulnerability detected")
            print(f"ETERNALBLUE-DETAILS: Remote code execution vulnerability in SMBv1")
            print(f"ETERNALBLUE-IMPACT: Critical - Remote code execution possible")
            print(f"ETERNALBLUE-RECOMMENDATION: Apply MS17-010 patch immediately")
            return True
        elif "NOT VULNERABLE" in stdout or "appears to be patched" in stdout:
            print(f"ETERNALBLUE-SAFE: {target}:{port} - System appears patched against MS17-010")
            return False
        else:
            print(f"ETERNALBLUE-UNKNOWN: {target}:{port} - Could not determine vulnerability status")
            print(f"ETERNALBLUE-OUTPUT: {stdout}")
            return False
        
    except subprocess.TimeoutExpired:
        print(f"ETERNALBLUE-TIMEOUT: {target}:{port} - Scan timed out")
        return False
    except Exception as e:
        print(f"ETERNALBLUE-ERROR: {target}:{port} - {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 eternalblue_check.py <target> <port>")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2]
    
    check_eternalblue(target, port)
