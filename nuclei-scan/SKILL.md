---
name: nuclei-scan
description: Nuclei template-based vulnerability scanning with severity filtering and structured output
license: MIT
metadata:
  category: vuln-analysis
  locale: en
  phase: v1
---

## What this skill does

Uses ProjectDiscovery's Nuclei to perform template-based vulnerability scanning against a target URL or list of hosts. Updates templates to the latest version, applies severity filters, runs the scan, and parses the JSON output to summarize findings.

## When to use

- When automatically detecting known vulnerability patterns (CVEs, default credentials, misconfigurations)
- When scanning multiple hosts quickly and in parallel
- When chaining `subdomain-enum` or `port-scan` results into vulnerability analysis
- When running automated security checks in a CI/CD pipeline

## Prerequisites

- Nuclei installed:
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- Go 1.21 or higher installed
- Environment variable `SECSKILL_TARGET` or `SECSKILL_TARGET_LIST` set to the scan target

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | One of the two | Single target URL or host |
| `SECSKILL_TARGET_LIST` | One of the two | Path to file containing list of targets |
| `SECSKILL_OUTPUT_DIR` | Optional | Directory to save results (default: `./output`) |
| `SECSKILL_SEVERITY` | Optional | Severity levels to filter (default: `medium,high,critical`) |
| `SECSKILL_TEMPLATES` | Optional | Template path or tag to use (default: all) |
| `SECSKILL_RATE_LIMIT` | Optional | Max requests per second (default: `150`) |

## Workflow

### Step 1: Environment setup and input validation

```bash
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SEVERITY="${SECSKILL_SEVERITY:-medium,high,critical}"
export RATE="${SECSKILL_RATE_LIMIT:-150}"
export TEMPLATES="${SECSKILL_TEMPLATES:-}"
mkdir -p "$OUTDIR"

# Configure target
if [ -n "${SECSKILL_TARGET:-}" ]; then
  TARGET_OPT="-u $SECSKILL_TARGET"
  SAFE_NAME=$(echo "$SECSKILL_TARGET" | tr '/:.' '___')
elif [ -n "${SECSKILL_TARGET_LIST:-}" ]; then
  if [ ! -f "$SECSKILL_TARGET_LIST" ]; then
    echo "[-] Target list file not found: $SECSKILL_TARGET_LIST"
    exit 1
  fi
  TARGET_OPT="-l $SECSKILL_TARGET_LIST"
  SAFE_NAME="list_$(basename "$SECSKILL_TARGET_LIST" .txt)"
else
  echo "[-] Set either SECSKILL_TARGET or SECSKILL_TARGET_LIST"
  exit 1
fi

echo "[*] Nuclei scan ready"
echo "[*] Severity filter : $SEVERITY"
echo "[*] Request rate    : $RATE req/s"
```

### Step 2: Update Nuclei templates

```bash
echo "[*] Updating templates..."
nuclei -update-templates 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[+] Templates updated successfully"
else
  echo "[-] Template update failed (proceeding with existing templates)"
fi
```

### Step 3: Run Nuclei scan

```bash
echo "[*] Starting Nuclei scan..."
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
JSON_OUT="$OUTDIR/nuclei_${SAFE_NAME}_${TIMESTAMP}.json"
TXT_OUT="$OUTDIR/nuclei_${SAFE_NAME}_${TIMESTAMP}.txt"

# Build template option
TMPL_OPT=""
if [ -n "$TEMPLATES" ]; then
  TMPL_OPT="-t $TEMPLATES"
fi

nuclei \
  $TARGET_OPT \
  -severity "$SEVERITY" \
  $TMPL_OPT \
  -rate-limit "$RATE" \
  -json-export "$JSON_OUT" \
  -output "$TXT_OUT" \
  -stats \
  -silent 2>/dev/null

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 1 ]; then
  echo "[-] Nuclei execution error (exit code: $EXIT_CODE)"
  exit $EXIT_CODE
fi
echo "[+] Scan complete"
```

### Step 4: Parse JSON results and summarize

```bash
echo "[*] Analyzing results..."

if [ ! -f "$JSON_OUT" ] || [ ! -s "$JSON_OUT" ]; then
  echo "[+] No vulnerabilities found (within the specified severity levels)"
  echo "Scan complete. No vulnerabilities found." > "$TXT_OUT"
else
  TOTAL=$(wc -l < "$JSON_OUT")
  echo "[!] Total findings: $TOTAL"

  echo ""
  echo "===== Summary by Severity ====="
  for SEV in critical high medium; do
    COUNT=$(grep -c "\"severity\":\"${SEV}\"" "$JSON_OUT" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && echo "  $SEV: $COUNT"
  done
  echo "==============================="
fi
```

### Step 5: Print details of high-risk findings

```bash
if [ -f "$JSON_OUT" ] && [ -s "$JSON_OUT" ]; then
  echo ""
  echo "===== Critical/High Findings ====="
  grep -E '"severity":"(critical|high)"' "$JSON_OUT" 2>/dev/null \
    | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        item = json.loads(line.strip())
        info = item.get('info', {})
        print(f\"  [{info.get('severity','?').upper()}] {info.get('name','?')}\")
        print(f\"    Template    : {item.get('template-id','?')}\")
        print(f\"    Target      : {item.get('host','?')}\")
        print(f\"    Matched URL : {item.get('matched-at','?')}\")
        print()
    except:
        pass
" 2>/dev/null || echo "  (parse error - check the raw JSON file)"
  echo "=================================="
fi
```

### Step 6: Print result summary

```bash
echo ""
echo "===== Nuclei Scan Result Summary ====="
echo "Severity filter : $SEVERITY"
echo "JSON output     : $JSON_OUT"
echo "Text output     : $TXT_OUT"
echo "======================================"
```

## Done when

- Nuclei scan completes without errors
- JSON result file is created (empty file if no findings)
- Per-severity summary is printed

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `nuclei: command not found` | Not installed or PATH issue | Ensure `$GOPATH/bin` is in PATH |
| Template update fails | Network issue | Proceed with existing templates; try manual update |
| Scan is slow | Rate limit too low | Increase with `SECSKILL_RATE_LIMIT=500` |
| Too many false positives | Template scope too broad | Narrow scope with `SECSKILL_TEMPLATES` tag |
| Connection errors | Target is offline | Verify target connectivity |

## Notes

- Only use against **pre-authorized targets**. Nuclei sends probes that actively verify vulnerabilities.
- Recommended starting point: `-severity critical,high` to identify the most important vulnerabilities first.
- Narrow scan scope with tags like `-tags cve,exposure,misconfig`.
- JSON output can be combined with the `cve-lookup` skill to supplement CVSS scores.
- Templates are stored by default in `~/.local/nuclei-templates/`.
