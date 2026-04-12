---
name: dependency-audit
description: Dependency vulnerability audit across Node.js, Python, and Go ecosystems
license: MIT
metadata:
  category: vuln-analysis
  locale: en
  phase: vuln-analysis
---

## What this skill does

Automatically detects the project type (Node.js, Python, Go, container) and runs the appropriate audit tool (`npm audit`, `pip-audit`, `trivy`). Aggregates discovered vulnerabilities by severity and outputs recommendations including fixed versions.

## When to use

- When checking dependency vulnerabilities before a code review or deployment
- When setting up an automated dependency security gate in a CI/CD pipeline
- When auditing accumulated vulnerabilities in an aging project all at once
- When scanning container images or filesystems for vulnerabilities

## Prerequisites

- Node.js projects: `npm` installed (included with Node.js)
- Python projects: `pip-audit` installed:
  ```bash
  pip install pip-audit
  ```
- Container/general use: `trivy` installed:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y wget apt-transport-https gnupg
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install -y trivy
  ```
- Environment variable `SECSKILL_PROJECT_PATH`: project root path

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_PROJECT_PATH` | Required | Project root path to audit |
| `SECSKILL_OUTPUT_DIR` | Optional | Directory to save results (default: `./output`) |
| `SECSKILL_MIN_SEVERITY` | Optional | Minimum severity filter `low/medium/high/critical` (default: `medium`) |
| `SECSKILL_TRIVY_TARGET` | Optional | trivy scan target (path or image name, default: project path) |

## Workflow

### Step 1: Environment setup and project type detection

```bash
export PROJECT="${SECSKILL_PROJECT_PATH:?Set the SECSKILL_PROJECT_PATH environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export MIN_SEV="${SECSKILL_MIN_SEVERITY:-medium}"
mkdir -p "$OUTDIR"

if [ ! -d "$PROJECT" ]; then
  echo "[-] Path not found: $PROJECT"
  exit 1
fi

echo "[*] Detecting project type: $PROJECT"

HAS_NPM=false
HAS_PYTHON=false
HAS_GO=false

[ -f "$PROJECT/package.json" ] && HAS_NPM=true && echo "[+] Node.js project detected (package.json)"
[ -f "$PROJECT/package-lock.json" ] || [ -f "$PROJECT/yarn.lock" ] && HAS_NPM=true
[ -f "$PROJECT/requirements.txt" ] || [ -f "$PROJECT/Pipfile" ] || [ -f "$PROJECT/pyproject.toml" ] && HAS_PYTHON=true && echo "[+] Python project detected"
[ -f "$PROJECT/go.mod" ] && HAS_GO=true && echo "[+] Go project detected (go.mod)"

SUMMARY_FILE="$OUTDIR/dependency_audit_summary.txt"
echo "Dependency Audit Report" > "$SUMMARY_FILE"
echo "Path : $PROJECT" >> "$SUMMARY_FILE"
echo "Date : $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
```

### Step 2: npm audit (Node.js)

```bash
if [ "$HAS_NPM" = "true" ]; then
  echo ""
  echo "[*] Running npm audit..."
  cd "$PROJECT"

  # Generate package-lock.json if missing
  if [ ! -f "package-lock.json" ] && [ ! -f "yarn.lock" ]; then
    echo "[*] Generating package-lock.json..."
    npm install --package-lock-only --silent 2>/dev/null
  fi

  npm audit \
    --audit-level="$MIN_SEV" \
    --json 2>/dev/null \
    > "$OUTDIR/npm_audit.json"

  NPM_TOTAL=$(jq '.metadata.vulnerabilities | (.critical + .high + .moderate + .low)' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  NPM_CRITICAL=$(jq '.metadata.vulnerabilities.critical' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  NPM_HIGH=$(jq '.metadata.vulnerabilities.high' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")

  echo "[+] npm audit complete: $NPM_TOTAL total (critical: $NPM_CRITICAL, high: $NPM_HIGH)"

  cat >> "$SUMMARY_FILE" << EOF
[ Node.js (npm audit) ]
Total vulnerabilities : $NPM_TOTAL
  Critical : $NPM_CRITICAL
  High     : $NPM_HIGH
  Moderate : $(jq '.metadata.vulnerabilities.moderate' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  Low      : $(jq '.metadata.vulnerabilities.low' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")

Fixable items:
$(jq -r '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") | "  - \(.key): \(.value.severity) -> \(.value.fixAvailable // "manual fix required")"' "$OUTDIR/npm_audit.json" 2>/dev/null | head -10)

EOF
  cd - > /dev/null
fi
```

### Step 3: pip-audit (Python)

```bash
if [ "$HAS_PYTHON" = "true" ]; then
  echo ""
  echo "[*] Running pip-audit..."

  PIP_AUDIT_ARGS=""
  if [ -f "$PROJECT/requirements.txt" ]; then
    PIP_AUDIT_ARGS="-r $PROJECT/requirements.txt"
  fi

  pip-audit \
    $PIP_AUDIT_ARGS \
    --format=json \
    --output="$OUTDIR/pip_audit.json" \
    2>/dev/null

  PIP_TOTAL=$(jq '[.[].vulns[]] | length' "$OUTDIR/pip_audit.json" 2>/dev/null || echo "0")
  echo "[+] pip-audit complete: $PIP_TOTAL findings"

  cat >> "$SUMMARY_FILE" << EOF
[ Python (pip-audit) ]
Total vulnerabilities : $PIP_TOTAL

Findings:
$(jq -r '.[] | select(.vulns | length > 0) | "  - \(.name) \(.version): \(.vulns | length) issue(s) (\(.vulns[0].id // "?"))"' "$OUTDIR/pip_audit.json" 2>/dev/null | head -10)

EOF
fi
```

### Step 4: trivy (Go and general)

```bash
if [ "$HAS_GO" = "true" ] || [ -f "$PROJECT/Dockerfile" ] || [ -f "$PROJECT/go.mod" ]; then
  echo ""
  echo "[*] Running trivy scan..."
  TRIVY_TARGET="${SECSKILL_TRIVY_TARGET:-$PROJECT}"

  if command -v trivy >/dev/null 2>&1; then
    trivy fs \
      --severity "$(echo $MIN_SEV | tr '[:lower:]' '[:upper:]'),HIGH,CRITICAL" \
      --format json \
      --output "$OUTDIR/trivy_audit.json" \
      --quiet \
      "$TRIVY_TARGET" 2>/dev/null

    TRIVY_TOTAL=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$OUTDIR/trivy_audit.json" 2>/dev/null || echo "0")
    echo "[+] trivy scan complete: $TRIVY_TOTAL findings"

    cat >> "$SUMMARY_FILE" << EOF
[ trivy (filesystem scan) ]
Total vulnerabilities : $TRIVY_TOTAL

Critical/High items:
$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "  - [\(.Severity)] \(.VulnerabilityID): \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion // "no fix available")"' "$OUTDIR/trivy_audit.json" 2>/dev/null | head -15)

EOF
  else
    echo "[-] trivy not installed. Skipping Go audit."
  fi
fi
```

### Step 5: Print overall summary

```bash
echo ""
echo "===== Dependency Audit Result Summary ====="
cat "$SUMMARY_FILE"
echo "==========================================="
echo "Detailed results:"
[ -f "$OUTDIR/npm_audit.json" ] && echo "  npm   : $OUTDIR/npm_audit.json"
[ -f "$OUTDIR/pip_audit.json" ] && echo "  pip   : $OUTDIR/pip_audit.json"
[ -f "$OUTDIR/trivy_audit.json" ] && echo "  trivy : $OUTDIR/trivy_audit.json"
echo "Summary : $SUMMARY_FILE"
```

## Done when

- The appropriate audit tool runs for each detected project type
- Vulnerability counts are aggregated by severity
- Summary file is created

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `npm audit` fails | Missing package-lock.json | Run `npm install` first |
| pip-audit error | Virtual environment not activated | Run `source venv/bin/activate` then retry |
| trivy DB download slow | Network speed issue | Pre-download with `trivy image --download-db-only` |
| No tools detected | Unsupported project structure | Specify path explicitly with `SECSKILL_TRIVY_TARGET` |

## Notes

- Use `npm audit fix` to automatically fix all auto-fixable vulnerabilities in bulk.
- pip-audit includes `pip install --upgrade <package>` recommendations.
- trivy scans OS packages, language-specific dependencies, and container images.
- For CI/CD integration, configure a build gate that fails the build when critical vulnerabilities are found.
