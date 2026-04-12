---
name: security-headers
description: Analyze HTTP security headers of a target URL and provide remediation advice
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Sends an HTTP request to the target URL, collects response headers, and checks for the presence and proper configuration of security-related headers. Classifies each header as present, missing, or misconfigured, and provides remediation recommendations for missing or improperly configured headers.

## When to use

- During web application security assessments (initial reconnaissance phase)
- When running a pre-deployment security checklist
- During bug bounty or penetration testing to quickly identify header vulnerabilities

## Prerequisites

- `curl` installed (included by default on most Linux/macOS systems)
- HTTP/HTTPS access to the target server

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Target URL to check (including scheme) | `https://example.com` |

## Workflow

### Step 1: Collect response headers

```bash
TARGET_URL="https://example.com"

curl -s -I -L \
  --max-time 10 \
  --user-agent "SecurityHeadersCheck/1.0" \
  "$TARGET_URL" 2>&1 | tee /tmp/headers_raw.txt

echo "=== Collected Headers ==="
cat /tmp/headers_raw.txt
```

### Step 2: Check individual security headers

```bash
check_header() {
  local name="$1"
  local pattern="$2"
  local value
  value=$(grep -i "^${pattern}:" /tmp/headers_raw.txt | head -1)
  if [ -z "$value" ]; then
    echo "[MISSING]  $name"
  else
    echo "[PRESENT]  $value"
  fi
}

echo ""
echo "=== Security Header Check Results ==="
check_header "X-Content-Type-Options"    "x-content-type-options"
check_header "X-Frame-Options"           "x-frame-options"
check_header "Strict-Transport-Security" "strict-transport-security"
check_header "Content-Security-Policy"   "content-security-policy"
check_header "X-XSS-Protection"          "x-xss-protection"
check_header "Referrer-Policy"           "referrer-policy"
check_header "Permissions-Policy"        "permissions-policy"
```

### Step 3: Detect misconfigured headers

```bash
echo ""
echo "=== Misconfiguration Check ==="

# HSTS: warn if max-age is too short
hsts=$(grep -i "^strict-transport-security:" /tmp/headers_raw.txt | head -1)
if [ -n "$hsts" ]; then
  max_age=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+')
  if [ -n "$max_age" ] && [ "$max_age" -lt 31536000 ]; then
    echo "[MISCONFIGURED] HSTS max-age=$max_age (recommended: 31536000 or higher)"
  else
    echo "[OK] HSTS max-age is sufficient"
  fi
fi

# X-XSS-Protection: warn if not set to 1; mode=block
xxp=$(grep -i "^x-xss-protection:" /tmp/headers_raw.txt | head -1)
if [ -n "$xxp" ]; then
  if echo "$xxp" | grep -qi "0"; then
    echo "[MISCONFIGURED] X-XSS-Protection: disabled with value 0"
  fi
fi

# X-Frame-Options: ALLOW-FROM is an outdated approach
xfo=$(grep -i "^x-frame-options:" /tmp/headers_raw.txt | head -1)
if [ -n "$xfo" ]; then
  if echo "$xfo" | grep -qi "allow-from"; then
    echo "[MISCONFIGURED] X-Frame-Options ALLOW-FROM is not supported by most browsers. Use CSP frame-ancestors instead."
  fi
fi
```

### Step 4: Output remediation recommendations

```bash
echo ""
echo "=== Remediation Recommendations ==="

grep -qi "^x-content-type-options:" /tmp/headers_raw.txt || \
  echo "X-Content-Type-Options: nosniff  # Prevent MIME type sniffing"

grep -qi "^x-frame-options:" /tmp/headers_raw.txt || \
  echo "X-Frame-Options: DENY  # Prevent clickjacking (or use Content-Security-Policy: frame-ancestors 'none')"

grep -qi "^strict-transport-security:" /tmp/headers_raw.txt || \
  echo "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload  # Enforce HTTPS"

grep -qi "^content-security-policy:" /tmp/headers_raw.txt || \
  echo "Content-Security-Policy: default-src 'self'  # Prevent XSS/data injection attacks (adjust policy to your application)"

grep -qi "^referrer-policy:" /tmp/headers_raw.txt || \
  echo "Referrer-Policy: strict-origin-when-cross-origin  # Limit Referer header information exposure"

grep -qi "^permissions-policy:" /tmp/headers_raw.txt || \
  echo "Permissions-Policy: geolocation=(), microphone=(), camera=()  # Restrict browser feature access"

echo ""
echo "Reference: https://securityheaders.com for detailed grading"
```

## Done when

- Each of the 7 security headers is judged as present, missing, or misconfigured
- Concrete header value examples are provided for missing or misconfigured headers

## Failure modes

| Symptom | Cause and Resolution |
|---------|---------------------|
| `curl: (6) Could not resolve host` | DNS not resolving. Check URL and network connectivity |
| `curl: (60) SSL certificate problem` | Self-signed certificate. Add `-k` flag (test environments only) |
| Headers are empty | CDN/proxy may be stripping headers. Consider checking the origin server directly |
| Different headers after 302/301 redirect | Use `-L` flag to follow redirects to the final destination |

## Notes

- `Content-Security-Policy` is complex; flagging it as missing results in a simple recommendation only. Actual configuration requires per-application review.
- `X-XSS-Protection` is deprecated in modern browsers. New projects should use CSP instead.
- HSTS cannot be applied to sites not using HTTPS.
