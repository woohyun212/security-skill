---
name: ioc-extract
description: Extract Indicators of Compromise (IOC) from text, logs, or files
license: MIT
metadata:
  category: incident-response
  locale: en
  phase: v1
---

## What this skill does

Automatically extracts Indicators of Compromise (IOCs) from text, log files, or URLs. Identifies IP addresses, domains, URLs, email addresses, and file hashes (MD5/SHA1/SHA256), then outputs a structured, defanged IOC list for safe sharing.

## When to use

- Identifying malicious infrastructure during incident response
- Extracting IOCs from threat intelligence reports or emails
- Collecting attacker indicators by analyzing log files
- Preparing an IOC list for ingestion into a SIEM or TIP

## Prerequisites

- Python 3.6 or higher
- (optional) ioc-finder library: `pip install ioc-finder`
- Input source: pasted text, local file path, or URL

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `INPUT_SOURCE` | Direct text, file path, or URL | `/var/log/apache2/access.log` |
| `OUTPUT_FORMAT` | Output format (text/json/csv) | `json` |

## Workflow

### Step 1: Confirm input source and collect text

```bash
# Read text from a file
INPUT_FILE="/path/to/log.txt"
if [ -f "$INPUT_FILE" ]; then
    TEXT=$(cat "$INPUT_FILE")
elif echo "$INPUT_FILE" | grep -qE '^https?://'; then
    TEXT=$(curl -sL "$INPUT_FILE")
else
    echo "Paste text and press Ctrl+D when done:"
    TEXT=$(cat)
fi
echo "$TEXT" > /tmp/ioc_input.txt
echo "[+] Input collected: $(wc -c < /tmp/ioc_input.txt) bytes"
```

### Step 2: Extract IOCs with ioc-finder (recommended)

```bash
# Check for ioc-finder installation and use it
if python3 -c "import ioc_finder" 2>/dev/null; then
    python3 - <<'PYEOF'
from ioc_finder import find_iocs
import json, sys

with open('/tmp/ioc_input.txt', 'r', errors='replace') as f:
    text = f.read()

iocs = find_iocs(text)

# Filter and clean results
result = {
    'ipv4': list(iocs.get('ipv4s', [])),
    'ipv6': list(iocs.get('ipv6s', [])),
    'domains': list(iocs.get('domains', [])),
    'urls': list(iocs.get('urls', [])),
    'emails': list(iocs.get('email_addresses', [])),
    'md5': list(iocs.get('md5s', [])),
    'sha1': list(iocs.get('sha1s', [])),
    'sha256': list(iocs.get('sha256s', [])),
}

total = sum(len(v) for v in result.values())
print(f"[+] Total {total} IOCs extracted")
with open('/tmp/ioc_raw.json', 'w') as f:
    json.dump(result, f, indent=2)
PYEOF
else
    echo "[!] ioc-finder not installed. Run pip install ioc-finder and retry."
    echo "[*] Falling back to regex-based extraction."
fi
```

### Step 3: Regex-based IOC extraction (fallback)

```bash
python3 - <<'PYEOF'
import re, json

with open('/tmp/ioc_input.txt', 'r', errors='replace') as f:
    text = f.read()

patterns = {
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    'domains': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|kr|ru|cn|info|biz|xyz|top|club|online|site|tech|dev|gov|edu|mil)\b',
    'urls': r'https?://[^\s\'"<>]+',
    'emails': r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    'md5': r'\b[0-9a-fA-F]{32}\b',
    'sha1': r'\b[0-9a-fA-F]{40}\b',
    'sha256': r'\b[0-9a-fA-F]{64}\b',
}

result = {}
for key, pat in patterns.items():
    matches = list(set(re.findall(pat, text)))
    result[key] = matches

total = sum(len(v) for v in result.values())
print(f"[+] Total {total} IOCs extracted (regex method)")
with open('/tmp/ioc_raw.json', 'w') as f:
    json.dump(result, f, indent=2)
PYEOF
```

### Step 4: Defang processing

```bash
python3 - <<'PYEOF'
import json, re

with open('/tmp/ioc_raw.json') as f:
    iocs = json.load(f)

def defang(value):
    # Replace dots with [.]
    value = re.sub(r'\.', '[.]', value)
    # Replace URL scheme
    value = re.sub(r'https?://', 'hxxp[://]', value)
    return value

defanged = {}
for key, values in iocs.items():
    if key in ('md5', 'sha1', 'sha256'):
        defanged[key] = values  # hashes do not need defanging
    else:
        defanged[key] = [defang(v) for v in values]

with open('/tmp/ioc_defanged.json', 'w') as f:
    json.dump(defanged, f, indent=2, ensure_ascii=False)
print("[+] Defang complete: /tmp/ioc_defanged.json")
PYEOF
```

### Step 5: Output structured IOC report

```bash
python3 - <<'PYEOF'
import json

with open('/tmp/ioc_defanged.json') as f:
    iocs = json.load(f)

labels = {
    'ipv4': 'IPv4 Addresses',
    'ipv6': 'IPv6 Addresses',
    'domains': 'Domains',
    'urls': 'URLs',
    'emails': 'Emails',
    'md5': 'MD5 Hashes',
    'sha1': 'SHA1 Hashes',
    'sha256': 'SHA256 Hashes',
}

print("=" * 60)
print("IOC Extraction Report")
print("=" * 60)
for key, label in labels.items():
    values = iocs.get(key, [])
    if values:
        print(f"\n[{label}] ({len(values)} items)")
        for v in values:
            print(f"  {v}")

print("\n[+] Raw JSON: /tmp/ioc_raw.json")
print("[+] Defanged JSON: /tmp/ioc_defanged.json")
PYEOF
```

## Done when

- Extracted IOCs are saved by category in `/tmp/ioc_raw.json`
- Defanged IOCs are saved in `/tmp/ioc_defanged.json`
- A categorized IOC list is printed to the terminal

## Failure modes

| Problem | Cause | Resolution |
|---------|-------|------------|
| ioc-finder ImportError | Package not installed | Run `pip install ioc-finder` |
| Empty results | Pattern mismatch or encoding issue | Check input file encoding with `file -i` |
| Excessive false positives | Overly broad regex patterns | Use ioc-finder instead, or apply an allowlist |
| URL fetch failure | curl not installed or network blocked | `sudo apt install curl` or paste manually |

## Notes

- Defanged IOCs cannot be accidentally clicked, making them safe to share.
- Manually review and exclude internal IP ranges (10.x, 172.16-31.x, 192.168.x) as needed.
- Extracted hashes can be fed into the `malware-hash` skill for VirusTotal lookups.
- For large logs (1 GB+), pre-filter suspicious lines with `grep` before applying this skill.
