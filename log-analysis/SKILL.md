---
name: log-analysis
description: Security log analysis and anomaly detection for access, auth, and syslog files
license: MIT
metadata:
  category: incident-response
  locale: en
  phase: v1
---

## What this skill does

Analyzes security log files to detect anomalies. Extracts top IPs, paths, status codes, and User-Agents from web access logs, and detects brute-force patterns (multiple 401s) and scanning behavior (sequential path enumeration). Extracts failed login patterns from auth logs and error/warning patterns from syslog, then outputs a summary report with a timeline.

## When to use

- Analyzing access logs when a web server compromise is suspected
- Checking whether an SSH brute-force attack has occurred
- Reconstructing an attack timeline during incident response
- Automating routine security monitoring and anomaly detection

## Prerequisites

- `grep`, `awk`, `sort`, `uniq` (available by default on most Linux systems)
- `python3` (advanced analysis and report generation)
- Read access to the target log files

## Inputs

| Field | Description | Example |
|-------|-------------|---------|
| `LOG_FILE` | Path to the log file to analyze | `/var/log/nginx/access.log` |
| `LOG_TYPE` | Log type: `access` / `auth` / `syslog` | `access` |
| `TOP_N` | Number of top entries to display (default: 20) | `20` |

## Workflow

### Step 1: Verify log file and type

```bash
LOG_FILE="${1:-}"
LOG_TYPE="${2:-auto}"
TOP_N="${3:-20}"

if [ -z "$LOG_FILE" ]; then
    read -rp "Enter log file path: " LOG_FILE
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "[!] File not found: $LOG_FILE"
    exit 1
fi

# Auto-detect log type
if [ "$LOG_TYPE" = "auto" ]; then
    filename=$(basename "$LOG_FILE")
    case "$filename" in
        access*|nginx*|apache*|httpd*) LOG_TYPE="access" ;;
        auth*|secure*|sshd*) LOG_TYPE="auth" ;;
        syslog*|messages*|system*) LOG_TYPE="syslog" ;;
        *) LOG_TYPE="access" ; echo "[*] Could not auto-detect log type, assuming access log." ;;
    esac
fi

TOTAL_LINES=$(wc -l < "$LOG_FILE")
FILE_SIZE=$(du -sh "$LOG_FILE" | cut -f1)
echo "[+] Log file: $LOG_FILE"
echo "    Type: $LOG_TYPE | Lines: $TOTAL_LINES | Size: $FILE_SIZE"
```

### Step 2: Web access log analysis

```bash
if [ "$LOG_TYPE" = "access" ]; then
    echo ""
    echo "=== Web Access Log Analysis ==="

    # Top IP addresses
    echo "[Top IP addresses] (Top $TOP_N)"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'

    # Top request paths
    echo ""
    echo "[Top request paths] (Top $TOP_N)"
    awk '{print $7}' "$LOG_FILE" | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'

    # HTTP status code distribution
    echo ""
    echo "[HTTP status code distribution]"
    awk '{print $9}' "$LOG_FILE" | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -rn | \
        awk '{printf "  %s: %d hits\n", $2, $1}'

    # Top User-Agents
    echo ""
    echo "[Top User-Agents] (Top 10)"
    awk -F'"' '{print $6}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10 | \
        awk '{printf "  %5d hits  %s\n", $1, substr($0, index($0,$2))}'
fi
```

### Step 3: Brute-force and scanning pattern detection

```bash
if [ "$LOG_TYPE" = "access" ]; then
    echo ""
    echo "=== Anomaly Detection ==="

    python3 - "$LOG_FILE" "$TOP_N" <<'PYEOF'
import sys, re
from collections import defaultdict

log_file = sys.argv[1]
top_n = int(sys.argv[2])

ip_401 = defaultdict(int)
ip_404 = defaultdict(int)
ip_paths = defaultdict(set)
suspicious_ips = set()

# Parse Combined Log Format
log_pattern = re.compile(r'(\S+) \S+ \S+ \[.*?\] "\S+ (\S+) \S+" (\d{3})')

with open(log_file, 'r', errors='replace') as f:
    for line in f:
        m = log_pattern.match(line)
        if not m:
            continue
        ip, path, status = m.group(1), m.group(2), m.group(3)

        if status == '401':
            ip_401[ip] += 1
        if status == '404':
            ip_404[ip] += 1
            ip_paths[ip].add(path)

# Brute-force: 10+ 401 errors from the same IP
print("\n[Suspected brute-force IPs] (10+ 401 errors)")
bf_found = False
for ip, count in sorted(ip_401.items(), key=lambda x: -x[1]):
    if count >= 10:
        print(f"  [!] {ip}: {count} authentication failures")
        suspicious_ips.add(ip)
        bf_found = True
if not bf_found:
    print("  [OK] No brute-force pattern detected")

# Scanning: 20+ 404 errors from the same IP (path enumeration)
print("\n[Suspected scanning IPs] (20+ 404 errors)")
scan_found = False
for ip, count in sorted(ip_404.items(), key=lambda x: -x[1]):
    if count >= 20:
        unique_paths = len(ip_paths[ip])
        print(f"  [!] {ip}: {count} 404 errors, {unique_paths} unique paths")
        suspicious_ips.add(ip)
        scan_found = True
if not scan_found:
    print("  [OK] No scanning pattern detected")

if suspicious_ips:
    print(f"\n[Summary] {len(suspicious_ips)} suspicious IP(s) found: {', '.join(suspicious_ips)}")
    # Suggest block commands
    print("\n[Example block commands (review before executing)]")
    for ip in list(suspicious_ips)[:5]:
        print(f"  # iptables -A INPUT -s {ip} -j DROP")
PYEOF
fi
```

### Step 4: Auth log analysis (auth/secure)

```bash
if [ "$LOG_TYPE" = "auth" ]; then
    echo ""
    echo "=== Auth Log Analysis ==="

    # Failed SSH logins
    echo "[Top IPs with failed SSH logins] (Top $TOP_N)"
    grep -i "failed password\|invalid user\|authentication failure" "$LOG_FILE" | \
        grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        awk '{print $2}' | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'

    echo ""
    echo "[Targeted user accounts] (Top $TOP_N)"
    grep -i "invalid user\|failed password for" "$LOG_FILE" | \
        grep -oE 'for [a-zA-Z0-9._-]+' | awk '{print $2}' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'

    echo ""
    echo "[Successful logins]"
    grep -i "accepted password\|accepted publickey" "$LOG_FILE" | \
        grep -oE 'for [a-zA-Z0-9._-]+ from [0-9.]+' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %4d hits  %s\n", $1, substr($0, index($0,$2))}'

    FAIL_COUNT=$(grep -ci "failed password\|invalid user" "$LOG_FILE" 2>/dev/null || echo 0)
    echo ""
    echo "[Summary] Total authentication failures: $FAIL_COUNT"
fi
```

### Step 5: Syslog analysis

```bash
if [ "$LOG_TYPE" = "syslog" ]; then
    echo ""
    echo "=== Syslog Analysis ==="

    echo "[Error/warning patterns (Top $TOP_N)]"
    grep -iE "error|warning|critical|alert|emerg|fail" "$LOG_FILE" | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /[Ee]rror|[Ww]arning|[Cc]ritical/) {key=$i; break}; print key}' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'

    echo ""
    echo "[Error frequency by process] (Top $TOP_N)"
    grep -iE "error|critical|emerg" "$LOG_FILE" | \
        awk '{print $5}' | sed 's/\[.*\]//' | sed 's/://' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d hits  %s\n", $1, $2}'
fi
```

### Step 6: Timeline and report output

```bash
python3 - "$LOG_FILE" "$LOG_TYPE" <<'PYEOF'
import sys, re
from collections import defaultdict

log_file = sys.argv[1]
log_type = sys.argv[2]

print("\n" + "=" * 60)
print("Timeline Summary")
print("=" * 60)

# Request count by hour
hourly = defaultdict(int)

if log_type == "access":
    time_pattern = re.compile(r'\[(\d{2}/\w+/\d{4}):(\d{2})')
elif log_type in ("auth", "syslog"):
    time_pattern = re.compile(r'(\w+ \d+ (\d{2}):\d{2}:\d{2})')

with open(log_file, 'r', errors='replace') as f:
    for line in f:
        m = time_pattern.search(line)
        if m:
            if log_type == "access":
                hour = m.group(2)
                date = m.group(1).split(':')[0]
                hourly[f"{date} {hour}:00"] += 1
            else:
                hour = m.group(2)
                hourly[f"{hour}:00"] += 1

print("\n[Requests/events per hour]")
peak = max(hourly.values()) if hourly else 1
for time_key in sorted(hourly.keys())[-24:]:
    count = hourly[time_key]
    bar = '#' * int(count / peak * 30)
    print(f"  {time_key}  {bar:<30} {count}")

print("\n[+] Analysis complete")
PYEOF
```

## Done when

- All analysis sections appropriate to the log type are printed
- Anomalies (brute-force/scanning/failure patterns) are reported as detected or not detected
- Hourly timeline is visualized
- Example block commands are shown for suspicious IPs (when applicable)

## Failure modes

| Problem | Cause | Solution |
|---------|-------|----------|
| Permission denied | No read access to log file | Use `sudo` or check permissions |
| Empty analysis output | Log format mismatch | Verify log format and adjust `awk` field numbers |
| python3 not installed | Missing Python | `sudo apt install python3` |
| Slow on large files | Log file > 1 GB | Extract recent entries with `tail -n 100000` |

## Notes

- Analysis results are for reference only. Always verify that suspected IPs are not legitimate traffic before blocking.
- For logs split across rotated files, chain them with `zcat *.gz | python3 ...`.
- For detected suspicious IPs, it is recommended to gather additional IOCs with the `ioc-extract` skill before correlating with `malware-hash`.
- Written against the Nginx/Apache Combined Log Format. For custom formats, adjust the `awk` field numbers accordingly.
