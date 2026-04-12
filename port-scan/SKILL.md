---
name: port-scan
description: Port scanning and service detection with nmap for authorized security assessments
license: MIT
metadata:
  category: recon
  locale: en
  phase: recon
---

## What this skill does

Uses nmap to detect open ports on a target host and collect service version and operating system information. Performs staged scanning from a fast top-port scan through detailed service version detection and OS fingerprinting, saving results in structured formats.

> **Important**: This skill must only be used on systems where **explicit written authorization** has been obtained. Unauthorized port scanning is illegal in most jurisdictions and violates terms of service.

## When to use

- Building a service inventory within a penetration testing scope
- Detecting unnecessarily exposed services
- Verifying service versions to map CVEs
- Periodically auditing network defense posture

## Prerequisites

- Install nmap:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y nmap
  # CentOS/RHEL
  sudo yum install -y nmap
  ```
- **Written authorization for the target system is required.**
- OS detection and some scan techniques require root/sudo privileges.
- Environment variable `SECSKILL_TARGET`: target IP, IP range, or hostname

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | Required | Scan target (IP, CIDR, hostname) |
| `SECSKILL_OUTPUT_DIR` | Optional | Output directory for results (default: `./output`) |
| `SECSKILL_SCAN_SPEED` | Optional | nmap speed template T1-T5 (default: `T3`) |
| `SECSKILL_TOP_PORTS` | Optional | Number of top ports to check in fast scan (default: `1000`) |

## Workflow

### Step 1: Confirm authorization and prepare environment

```bash
export TARGET="${SECSKILL_TARGET:?Set the SECSKILL_TARGET environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SPEED="${SECSKILL_SCAN_SPEED:-T3}"
export TOP_PORTS="${SECSKILL_TOP_PORTS:-1000}"
mkdir -p "$OUTDIR"

echo "================================================================"
echo " WARNING: This scan must only be performed on authorized targets."
echo " Unauthorized scanning is illegal and carries legal liability."
echo "================================================================"
echo "[*] Scan target: $TARGET"
echo "[*] Output path: $OUTDIR"

SAFE_NAME=$(echo "$TARGET" | tr '/:' '__')
```

### Step 2: Fast top-port scan

```bash
echo "[*] Step 1: Starting fast scan of top $TOP_PORTS ports..."
nmap -$SPEED \
  --top-ports "$TOP_PORTS" \
  -oN "$OUTDIR/quick_scan_${SAFE_NAME}.txt" \
  -oX "$OUTDIR/quick_scan_${SAFE_NAME}.xml" \
  "$TARGET" 2>/dev/null

echo "[+] Fast scan complete"
echo "[*] Discovered open ports:"
grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt" | tee /tmp/open_ports.txt
OPEN_COUNT=$(wc -l < /tmp/open_ports.txt)
echo "[+] Open port count: $OPEN_COUNT"
```

### Step 3: Detailed service version scan

```bash
# Extract open ports only for detailed scan
OPEN_PORTS=$(grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt" \
  | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
  echo "[-] No open ports found. Exiting scan."
  exit 0
fi

echo "[*] Step 2: Detailed service version scan (ports: $OPEN_PORTS)..."
nmap -$SPEED \
  -p "$OPEN_PORTS" \
  -sV \
  --version-intensity 7 \
  -sC \
  -oN "$OUTDIR/service_scan_${SAFE_NAME}.txt" \
  -oX "$OUTDIR/service_scan_${SAFE_NAME}.xml" \
  "$TARGET" 2>/dev/null

echo "[+] Service version scan complete"
```

### Step 4: OS detection (requires root)

```bash
echo "[*] Step 3: Attempting OS detection..."
if [ "$(id -u)" -eq 0 ]; then
  nmap -$SPEED \
    -p "$OPEN_PORTS" \
    -O \
    --osscan-guess \
    -oN "$OUTDIR/os_scan_${SAFE_NAME}.txt" \
    "$TARGET" 2>/dev/null

  OS_INFO=$(grep -iE "OS details:|Aggressive OS guesses:" "$OUTDIR/os_scan_${SAFE_NAME}.txt" | head -3)
  echo "[+] OS detection results:"
  echo "${OS_INFO:-(OS detection failed - more open ports may be required)}"
else
  echo "[-] OS detection skipped (root required). Re-run with sudo to enable."
fi
```

### Step 5: UDP key service scan (optional, requires root)

```bash
if [ "$(id -u)" -eq 0 ]; then
  echo "[*] Step 4: UDP key service scan (DNS/SNMP/NTP etc.)..."
  nmap -$SPEED \
    -sU \
    -p 53,67,68,69,123,161,162,500,514,1900 \
    -oN "$OUTDIR/udp_scan_${SAFE_NAME}.txt" \
    "$TARGET" 2>/dev/null
  echo "[+] UDP scan complete"
else
  echo "[-] UDP scan skipped (root required)"
fi
```

### Step 6: Results summary

```bash
echo ""
echo "===== Port Scan Results Summary ====="
echo "Target         : $TARGET"
echo "Open port count: $OPEN_COUNT"
echo ""
echo "[ Service list ]"
grep "^[0-9].*open" "$OUTDIR/service_scan_${SAFE_NAME}.txt" 2>/dev/null \
  || grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt"
echo ""
echo "Output files:"
echo "  - $OUTDIR/quick_scan_${SAFE_NAME}.txt"
echo "  - $OUTDIR/service_scan_${SAFE_NAME}.txt"
echo "  - $OUTDIR/service_scan_${SAFE_NAME}.xml (structured data)"
echo "====================================="
```

## Done when

- Fast scan and service version scan result files are created
- Structured XML result files are saved
- Open port list and service information are printed

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `nmap: command not found` | Not installed | Run `apt-get install nmap` |
| All ports filtered | Firewall or IPS blocking | Add `-Pn` flag, try different scan techniques |
| Scan is very slow | Network latency or T1/T2 speed | Increase with `SECSKILL_SCAN_SPEED=T4` |
| OS detection failed | Insufficient open ports or no privileges | Run with sudo, retry after scanning more ports |
| Connection refused | Target offline or filtered | Skip ping with `-Pn` |

## Notes

- **Legal warning**: Unauthorized port scanning may be subject to criminal prosecution. Always obtain written authorization.
- `-T4` or `-T5` are likely to trigger IDS/IPS alerts. Use `-T1` or `-T2` for stealth testing.
- XML output can be integrated with the `nuclei-scan` skill and vulnerability management platforms.
- NSE scripts (`-sC`) also perform some basic vulnerability checks (e.g. SMB signing, SSL certificate info).
