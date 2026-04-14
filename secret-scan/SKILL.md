---
name: secret-scan
description: Secret and credential detection in source code and git history using trufflehog or gitleaks
license: MIT
metadata:
  category: vuln-analysis
  locale: en
  phase: v1
---

## What this skill does

Detects API keys, passwords, tokens, and private keys in source code and git history using trufflehog or gitleaks. Classifies discovered secrets by type and provides remediation recommendations.

## When to use

- Before publishing code to a public repository to check for secret leaks
- During security audits to detect hardcoded credentials in source code
- During incident response to check git history for past secret exposures
- In CI/CD pipelines to automatically block commits containing secrets

## Prerequisites

- trufflehog installed (recommended):
  ```bash
  go install github.com/trufflesecurity/trufflehog/v3@latest
  ```
- Or gitleaks installed (alternative):
  ```bash
  # Ubuntu/Debian
  GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4)
  wget -q "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
  ```
- Environment variable `SECSKILL_SCAN_PATH`: path to scan (git repository or directory)

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_SCAN_PATH` | required | Path to scan (git repository root recommended) |
| `SECSKILL_OUTPUT_DIR` | optional | Output directory for results (default: `./output`) |
| `SECSKILL_SCAN_TOOL` | optional | `trufflehog` or `gitleaks` (default: auto-detect) |
| `SECSKILL_SCAN_GIT_HISTORY` | optional | Set to `true` to scan full git history (default: `true`) |

## Workflow

### Step 1: Environment setup and tool detection

```bash
export SCAN_PATH="${SECSKILL_SCAN_PATH:?Set the SECSKILL_SCAN_PATH environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SCAN_GIT="${SECSKILL_SCAN_GIT_HISTORY:-true}"
mkdir -p "$OUTDIR"

if [ ! -e "$SCAN_PATH" ]; then
  echo "[-] Path not found: $SCAN_PATH"
  exit 1
fi

# Auto-detect tool
if [ -n "${SECSKILL_SCAN_TOOL:-}" ]; then
  TOOL="$SECSKILL_SCAN_TOOL"
elif command -v trufflehog >/dev/null 2>&1; then
  TOOL="trufflehog"
elif command -v gitleaks >/dev/null 2>&1; then
  TOOL="gitleaks"
else
  echo "[-] Please install either trufflehog or gitleaks"
  exit 1
fi

echo "[*] Starting secret scan"
echo "[*] Scan tool: $TOOL"
echo "[*] Target path: $SCAN_PATH"
SAFE_NAME=$(basename "$SCAN_PATH")
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
```

### Step 2: trufflehog - git history scan

```bash
if [ "$TOOL" = "trufflehog" ]; then
  echo "[*] Scanning git history with trufflehog..."
  JSON_OUT="$OUTDIR/trufflehog_${SAFE_NAME}_${TIMESTAMP}.json"

  IS_GIT=false
  [ -d "$SCAN_PATH/.git" ] && IS_GIT=true

  if [ "$IS_GIT" = "true" ] && [ "$SCAN_GIT" = "true" ]; then
    trufflehog git \
      "file://$SCAN_PATH" \
      --json \
      --no-update \
      2>/dev/null \
      > "$JSON_OUT"
    echo "[+] Git history scan complete"
  fi

  # Scan current files
  echo "[*] Scanning current files..."
  FS_OUT="$OUTDIR/trufflehog_fs_${SAFE_NAME}_${TIMESTAMP}.json"
  trufflehog filesystem \
    "$SCAN_PATH" \
    --json \
    --no-update \
    2>/dev/null \
    > "$FS_OUT"
  echo "[+] Filesystem scan complete"

  # Merge results
  cat "$JSON_OUT" "$FS_OUT" 2>/dev/null \
    | grep -v '^$' \
    > "$OUTDIR/secrets_combined_${SAFE_NAME}.json" || true
  COMBINED="$OUTDIR/secrets_combined_${SAFE_NAME}.json"
fi
```

### Step 3: gitleaks - scan execution (alternative)

```bash
if [ "$TOOL" = "gitleaks" ]; then
  echo "[*] Scanning with gitleaks..."
  GITLEAKS_OUT="$OUTDIR/gitleaks_${SAFE_NAME}_${TIMESTAMP}.json"

  IS_GIT=false
  [ -d "$SCAN_PATH/.git" ] && IS_GIT=true

  if [ "$IS_GIT" = "true" ]; then
    DETECT_CMD="git -p $SCAN_PATH"
    [ "$SCAN_GIT" != "true" ] && DETECT_CMD="dir $SCAN_PATH"
    gitleaks detect \
      --source="$SCAN_PATH" \
      --report-format=json \
      --report-path="$GITLEAKS_OUT" \
      --no-banner \
      2>/dev/null || true
  else
    gitleaks detect \
      --source="$SCAN_PATH" \
      --no-git \
      --report-format=json \
      --report-path="$GITLEAKS_OUT" \
      --no-banner \
      2>/dev/null || true
  fi

  COMBINED="$GITLEAKS_OUT"
  echo "[+] gitleaks scan complete"
fi
```

### Step 4: Finding classification and summary

```bash
echo "[*] Classifying findings..."
SUMMARY_FILE="$OUTDIR/secrets_summary_${SAFE_NAME}.txt"

if [ ! -f "$COMBINED" ] || [ ! -s "$COMBINED" ]; then
  echo "[+] No secrets found" | tee "$SUMMARY_FILE"
else
  TOTAL=$(grep -c '"' "$COMBINED" 2>/dev/null | head -1 || echo "unknown")

  cat > "$SUMMARY_FILE" << 'EOF'
===== Secret Scan Results =====
EOF

  if [ "$TOOL" = "trufflehog" ]; then
    FINDING_COUNT=$(wc -l < "$COMBINED")
    echo "Total findings: $FINDING_COUNT" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "[ By Type ]" >> "$SUMMARY_FILE"
    python3 -c "
import sys, json
from collections import Counter
counts = Counter()
findings = []
with open('$COMBINED') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            det = item.get('DetectorName', item.get('detector_name', 'unknown'))
            counts[det] += 1
            findings.append(item)
        except:
            pass
for det, cnt in counts.most_common():
    print(f'  {det}: {cnt} finding(s)')
print()
print('[ Finding Details (top 20) ]')
for item in findings[:20]:
    det = item.get('DetectorName', item.get('detector_name', '?'))
    raw = item.get('Raw', item.get('raw', ''))
    file = item.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')
    if not file:
        file = item.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'unknown')
    masked = str(raw)[:6] + '***' + str(raw)[-4:] if len(str(raw)) > 10 else '***'
    print(f'  [{det}] File: {file}')
    print(f'    Value (masked): {masked}')
" 2>/dev/null >> "$SUMMARY_FILE" || echo "(Parse error - check JSON file directly)" >> "$SUMMARY_FILE"
  fi

  if [ "$TOOL" = "gitleaks" ]; then
    python3 -c "
import sys, json
try:
    with open('$COMBINED') as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]
    from collections import Counter
    counts = Counter(item.get('RuleID','?') for item in data)
    print(f'Total findings: {len(data)}')
    print()
    print('[ By Type ]')
    for rule, cnt in counts.most_common():
        print(f'  {rule}: {cnt} finding(s)')
    print()
    print('[ Finding Details (top 20) ]')
    for item in data[:20]:
        secret = item.get('Secret','')
        masked = secret[:4] + '***' if len(secret) > 4 else '***'
        print(f'  [{item.get(\"RuleID\",\"?\")}] {item.get(\"File\",\"?\")}:{item.get(\"StartLine\",\"?\")}')
        print(f'    Value (masked): {masked}')
except Exception as e:
    print(f'Parse error: {e}')
" 2>/dev/null >> "$SUMMARY_FILE"
  fi
fi
```

### Step 5: Remediation recommendations

```bash
cat >> "$SUMMARY_FILE" << 'EOF'

===== Remediation Recommendations =====
1. Immediately revoke all discovered secrets and issue new credentials.
2. To remove secrets from git history, use BFG Repo Cleaner or git-filter-repo.
3. Use environment variables or secret management services (AWS Secrets Manager, HashiCorp Vault, etc.).
4. Integrate gitleaks into a pre-commit hook to block future commits:
   gitleaks protect --staged -v
5. Add .env, *.pem, *.key, config/secrets.* to .gitignore.
========================================
EOF

echo ""
cat "$SUMMARY_FILE"
echo ""
echo "Results file: $SUMMARY_FILE"
[ -f "$COMBINED" ] && echo "Raw JSON: $COMBINED"
```

## Done when

- Scan tool runs without errors
- Findings are classified by type
- Remediation recommendations are printed
- Results file is created

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `trufflehog: command not found` | Not installed or PATH issue | Check `$GOPATH/bin` in PATH and reinstall |
| Slow on large repositories | Extensive git history | Limit scope with `--since-commit HEAD~100` |
| Too many false positives | Default rules are broad | Tune rules with gitleaks `.gitleaks.toml` config |
| JSON parse error | Empty result or format change | Check raw file directly |

## Notes

- If secrets are found, immediately revoking credentials takes priority over rewriting git history.
- trufflehog supports real-time secret validation with `--only-verified`.
- For pre-commit integration: `pip install pre-commit`, then add gitleaks to `.pre-commit-config.yaml`.
- Platforms like GitHub and GitLab have built-in secret scanning features. Enable these as a complementary measure.
- Never expose discovered secret values in logs, issue trackers, Slack, etc. Always mask them.
