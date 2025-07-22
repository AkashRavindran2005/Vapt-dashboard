TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "[$(date)] Starting EternalBlue check for $TARGET"
nmap -p 445 --script smb-vuln-ms17-010 --script-args vulns.showall $TARGET
echo "[$(date)] EternalBlue check completed for $TARGET"
