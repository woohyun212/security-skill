---
name: insecure-defaults
description: Detect insecure default configurations including weak crypto, fail-open patterns, default credentials, and unsafe framework settings
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Scans source code for insecure default configurations across five risk categories: weak cryptographic algorithms, hardcoded or default credentials, fail-open error handling patterns, unsafe framework defaults, and insecure TLS/SSL settings. For each finding it reports the file location, explains the risk, and recommends a secure replacement.

## When to use

- During code reviews to catch insecure defaults before they reach production
- As part of security audits on new or unfamiliar codebases
- Before deploying a service to check framework and runtime settings
- When reviewing third-party or legacy code inherited by the team

## Prerequisites

- `grep` (standard, always available)
- `semgrep` (optional, improves accuracy with structural matching):
  ```bash
  pip install semgrep
  # verify
  semgrep --version
  ```
- Environment variable `SECSKILL_SCAN_PATH`: root directory of the codebase to scan

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_SCAN_PATH` | required | Root directory of the codebase to scan |
| `SECSKILL_OUTPUT_DIR` | optional | Output directory for results (default: `./output`) |
| `SECSKILL_EXTENSIONS` | optional | Comma-separated file extensions to include (default: `py,js,ts,java,go,rb,php,cs,cpp,c,yaml,yml,toml,env,cfg,conf,ini,properties`) |
| `SECSKILL_USE_SEMGREP` | optional | Set to `false` to skip semgrep even if installed (default: auto-detect) |

## Workflow

### Step 1: Environment setup

```bash
export SCAN_PATH="${SECSKILL_SCAN_PATH:?Set SECSKILL_SCAN_PATH to the codebase root}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export EXTENSIONS="${SECSKILL_EXTENSIONS:-py,js,ts,java,go,rb,php,cs,cpp,c,yaml,yml,toml,env,cfg,conf,ini,properties}"
mkdir -p "$OUTDIR"

if [ ! -d "$SCAN_PATH" ]; then
  echo "[-] Directory not found: $SCAN_PATH"
  exit 1
fi

SAFE_NAME=$(basename "$SCAN_PATH")
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
REPORT="$OUTDIR/insecure_defaults_${SAFE_NAME}_${TIMESTAMP}.txt"

# Build grep include flags from extension list
GREP_INCLUDES=$(echo "$EXTENSIONS" | tr ',' '\n' | sed 's/^/--include=*./' | tr '\n' ' ')

USE_SEMGREP=false
if [ "${SECSKILL_USE_SEMGREP:-auto}" != "false" ] && command -v semgrep >/dev/null 2>&1; then
  USE_SEMGREP=true
fi

echo "===== Insecure Defaults Scan =====" | tee "$REPORT"
echo "Target : $SCAN_PATH"                | tee -a "$REPORT"
echo "Time   : $TIMESTAMP"               | tee -a "$REPORT"
echo "Semgrep: $USE_SEMGREP"             | tee -a "$REPORT"
echo ""                                   | tee -a "$REPORT"
```

### Step 2: Weak cryptographic algorithms

Flags use of broken or weak algorithms: MD5, SHA1, DES, RC4, and AES in ECB mode.

```bash
echo "--- [1/5] Weak Cryptographic Algorithms ---" | tee -a "$REPORT"

WEAK_CRYPTO_PATTERNS=(
  'MD5\|md5\|hashlib\.md5\|MessageDigest\.getInstance("MD5")\|crypto\.createHash("md5")'
  'SHA1\b\|sha1\b\|hashlib\.sha1\|MessageDigest\.getInstance("SHA-1")\|crypto\.createHash("sha1")'
  '\bDES\b\|DESede\|TripleDES\|Cipher\.getInstance("DES'
  '\bRC4\b\|ARCFOUR\|crypto\.createCipheriv("rc4")'
  'AES/ECB\|AES_ECB\|mode=ECB\|modes\.ECB'
)

CRYPTO_FOUND=0
for pattern in "${WEAK_CRYPTO_PATTERNS[@]}"; do
  results=$(grep -rn $GREP_INCLUDES -E "$pattern" "$SCAN_PATH" 2>/dev/null | grep -v 'test\|spec\|_test\.' | head -20)
  if [ -n "$results" ]; then
    echo "$results" | tee -a "$REPORT"
    CRYPTO_FOUND=$((CRYPTO_FOUND + 1))
  fi
done

if [ "$USE_SEMGREP" = "true" ]; then
  semgrep --config "r/python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithms" \
          --config "r/java.lang.security.audit.crypto.weak-hash.use-of-md5" \
          --config "r/java.lang.security.audit.crypto.weak-hash.use-of-sha1" \
          --json "$SCAN_PATH" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    results = data.get('results', [])
    for r in results:
        print(f'  [semgrep] {r[\"path\"]}:{r[\"start\"][\"line\"]} - {r[\"check_id\"]}')
except: pass
" | tee -a "$REPORT"
fi

[ "$CRYPTO_FOUND" -eq 0 ] && echo "  [ok] No weak crypto patterns found" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
```

### Step 3: Default and hardcoded credentials

Flags literal passwords, default admin credentials, and hardcoded API tokens in code and config files.

```bash
echo "--- [2/5] Default / Hardcoded Credentials ---" | tee -a "$REPORT"

CRED_PATTERNS=(
  'password\s*=\s*["'"'"'][^"'"'"']{1,32}["'"'"']'
  'passwd\s*=\s*["'"'"'][^"'"'"']{1,32}["'"'"']'
  'secret\s*=\s*["'"'"'][^"'"'"']{1,64}["'"'"']'
  'api_key\s*=\s*["'"'"'][^"'"'"']{8,}["'"'"']'
  'default_password\|DEFAULT_PASSWORD\|admin:admin\|admin:password\|root:root\|changeme\|changeit'
  'HARDCODED\|hardcoded.*password\|password.*hardcoded'
)

CRED_FOUND=0
for pattern in "${CRED_PATTERNS[@]}"; do
  results=$(grep -rni $GREP_INCLUDES -E "$pattern" "$SCAN_PATH" 2>/dev/null \
    | grep -v '\.git/\|node_modules/\|vendor/\|test\|spec\|example\|sample\|placeholder' \
    | head -20)
  if [ -n "$results" ]; then
    # Mask values before printing
    echo "$results" | sed 's/\(=\s*["'"'"']\)[^"'"'"']*\(["'"'"']\)/\1***\2/g' | tee -a "$REPORT"
    CRED_FOUND=$((CRED_FOUND + 1))
  fi
done

[ "$CRED_FOUND" -eq 0 ] && echo "  [ok] No default credential patterns found" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
```

### Step 4: Fail-open patterns

Flags broad exception handlers that silently continue instead of failing safely, which can bypass authentication, authorization, or validation logic.

```bash
echo "--- [3/5] Fail-Open Patterns ---" | tee -a "$REPORT"

FAILOPEN_PATTERNS=(
  'except\s*:\s*pass'
  'except\s*Exception\s*:\s*pass'
  'catch\s*(\s*Exception\s*)\s*\{\s*\}'
  'catch\s*(\s*Throwable\s*)\s*\{\s*\}'
  'rescue\s*=>\s*[a-z_]*\s*\n\s*end'
  'on_error\s*:\s*continue\|ignore_errors\s*=\s*true'
  'silenceErrors\|suppressErrors\|swallow.*exception\|swallowException'
)

FAILOPEN_FOUND=0
for pattern in "${FAILOPEN_PATTERNS[@]}"; do
  results=$(grep -rn $GREP_INCLUDES -E "$pattern" "$SCAN_PATH" 2>/dev/null \
    | grep -v 'test\|spec\|_test\.' \
    | head -20)
  if [ -n "$results" ]; then
    echo "$results" | tee -a "$REPORT"
    FAILOPEN_FOUND=$((FAILOPEN_FOUND + 1))
  fi
done

[ "$FAILOPEN_FOUND" -eq 0 ] && echo "  [ok] No obvious fail-open patterns found" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
```

### Step 5: Insecure framework defaults

Checks for common unsafe framework settings: Django DEBUG mode, wildcard CORS, permissive Content-Security-Policy, and disabled security middleware.

```bash
echo "--- [4/5] Insecure Framework Defaults ---" | tee -a "$REPORT"

FRAMEWORK_PATTERNS=(
  'DEBUG\s*=\s*True\b'
  'ALLOWED_HOSTS\s*=\s*\[\s*["'"'"']\*["'"'"']\s*\]'
  'CORS_ORIGIN_ALLOW_ALL\s*=\s*True\|cors.*origins.*\*\|Access-Control-Allow-Origin.*\*'
  "Content-Security-Policy.*unsafe-inline.*unsafe-eval\|csp.*'unsafe-eval'"
  'SESSION_COOKIE_SECURE\s*=\s*False\|CSRF_COOKIE_SECURE\s*=\s*False'
  'SECURITY_HSTS_SECONDS\s*=\s*0\|SECURE_HSTS_SECONDS\s*=\s*0'
  'helmet\s*(\s*)\|app\.disable\s*(\s*["'"'"']x-powered-by["'"'"']\s*)'
  'verify\s*=\s*False\b\|ssl_verify\s*=\s*false\b\|VERIFY_SSL\s*=\s*false'
)

FRAMEWORK_FOUND=0
for pattern in "${FRAMEWORK_PATTERNS[@]}"; do
  results=$(grep -rn $GREP_INCLUDES -E "$pattern" "$SCAN_PATH" 2>/dev/null \
    | grep -v '\.git/\|node_modules/\|vendor/' \
    | head -20)
  if [ -n "$results" ]; then
    echo "$results" | tee -a "$REPORT"
    FRAMEWORK_FOUND=$((FRAMEWORK_FOUND + 1))
  fi
done

[ "$FRAMEWORK_FOUND" -eq 0 ] && echo "  [ok] No insecure framework defaults found" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
```

### Step 6: Unsafe TLS/SSL defaults

Flags disabled certificate verification, acceptance of expired certificates, and use of deprecated TLS versions.

```bash
echo "--- [5/5] Unsafe TLS/SSL Defaults ---" | tee -a "$REPORT"

TLS_PATTERNS=(
  'verify\s*=\s*False\b\|verify_ssl\s*=\s*False\|checkServerIdentity\s*:\s*\(\s*\)\s*=>'
  'ssl\.CERT_NONE\|CERT_NONE\|rejectUnauthorized\s*:\s*false'
  'TLSv1\b\|TLSv1_0\|TLSv1_1\|ssl\.PROTOCOL_TLSv1\b\|ssl\.PROTOCOL_TLSv1_1\b'
  'SSLv2\|SSLv3\|ssl\.PROTOCOL_SSLv2\|ssl\.PROTOCOL_SSLv3'
  'InsecureRequestWarning\|urllib3.*disable_warnings\|requests\.packages\.urllib3\.disable_warnings'
  'allow_expired\s*=\s*true\|ignore_ssl_errors\s*=\s*true'
)

TLS_FOUND=0
for pattern in "${TLS_PATTERNS[@]}"; do
  results=$(grep -rn $GREP_INCLUDES -E "$pattern" "$SCAN_PATH" 2>/dev/null \
    | grep -v '\.git/\|node_modules/\|vendor/\|test\|spec' \
    | head -20)
  if [ -n "$results" ]; then
    echo "$results" | tee -a "$REPORT"
    TLS_FOUND=$((TLS_FOUND + 1))
  fi
done

[ "$TLS_FOUND" -eq 0 ] && echo "  [ok] No unsafe TLS/SSL defaults found" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
```

### Step 7: Risk summary and recommendations

```bash
TOTAL_ISSUES=$((CRYPTO_FOUND + CRED_FOUND + FAILOPEN_FOUND + FRAMEWORK_FOUND + TLS_FOUND))

cat >> "$REPORT" << EOF
===== Risk Summary =====
Weak crypto algorithms  : $CRYPTO_FOUND category(s) with findings
Default credentials     : $CRED_FOUND category(s) with findings
Fail-open patterns      : $FAILOPEN_FOUND category(s) with findings
Framework defaults      : $FRAMEWORK_FOUND category(s) with findings
Unsafe TLS/SSL          : $TLS_FOUND category(s) with findings
Total flagged categories: $TOTAL_ISSUES / 5

===== Remediation Priority =====
HIGH   - Any disabled TLS verification or hardcoded credentials -> fix immediately
HIGH   - Fail-open handlers protecting auth/authz paths -> audit and add explicit failure
MEDIUM - Weak crypto used for password hashing or signatures -> migrate to SHA-256+ or bcrypt/argon2
MEDIUM - Framework debug mode or wildcard CORS in non-local config -> disable before deploy
LOW    - Weak crypto used only for non-security checksums (e.g., cache keys) -> document intent

===== Secure Defaults Reference =====
Crypto    : SHA-256, SHA-3, AES-GCM (128/256-bit), ChaCha20-Poly1305, bcrypt/argon2 for passwords
TLS       : TLS 1.2+ with certificate verification enabled, HSTS enabled
Passwords : Inject via environment variable or secrets manager; never hardcode
CORS      : Explicit allowlist of trusted origins; never use * in production
CSP       : Restrict to specific sources; avoid 'unsafe-inline' and 'unsafe-eval'
Errors    : Log the error, return a failure response; never silently proceed
=================================
EOF

echo ""
cat "$REPORT"
echo ""
echo "Report saved to: $REPORT"
```

## Done when

- All five categories have been scanned and results printed
- Each finding includes file path and line number
- Risk summary table is generated
- Report file is written to the output directory

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `grep: invalid option` | Shell incompatibility with pattern quoting | Run with `bash` explicitly; simplify the pattern escaping |
| Too many false positives in test files | Test fixtures contain intentional weak defaults | Add project-specific paths to the `grep -v` exclusions |
| semgrep rules not found | Rule IDs change across semgrep releases | Check available rules with `semgrep --config auto` or visit semgrep.dev |
| Missing findings for compiled languages | Grep cannot inspect bytecode | Run on source before compilation; add `.class`/`.pyc` to exclusions |
| Credential values appear in report | Masking sed pattern did not match quoting style | Review and extend the `sed` mask expression for the quoting style used |

## Notes

- Findings in `test/`, `spec/`, and `*_test.*` files are filtered by default because test fixtures intentionally use weak values. Re-include them if you want full coverage of test code.
- This skill uses static pattern matching; it cannot evaluate runtime configuration or environment-variable-injected values. Always complement with manual review of deployment configs.
- This skill pairs well with `secret-scan` (credential leaks in git history) and `security-headers` (HTTP-level defaults).
- Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
