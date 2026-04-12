---
name: waf-detect
description: Detect the presence and type of a Web Application Firewall using wafw00f or manual fingerprinting
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects whether a WAF (Web Application Firewall) is present in front of a target URL using the `wafw00f` tool or manual curl fingerprinting, and identifies the specific WAF product — Cloudflare, AWS WAF, Akamai, F5 BIG-IP, and others.

## When to use

- Before formulating a WAF bypass strategy during the initial reconnaissance phase of a pentest or bug bounty engagement
- When verifying that your own service's WAF is functioning correctly
- When suspecting a WAF as the cause of false positives or false negatives from a scanner

## Prerequisites

- Python 3 and pip required (for `wafw00f` installation)
- `curl` required (manual fallback method)
- HTTP/HTTPS access to the target URL

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Target URL to test | `https://example.com` |

## Workflow

### Step 1: Install wafw00f (if not installed)

```bash
# Check for wafw00f and install if missing
if ! command -v wafw00f &>/dev/null; then
  echo "wafw00f not found. Installing..."
  pip install wafw00f --quiet
else
  echo "wafw00f already installed: $(wafw00f --version 2>&1 | head -1)"
fi
```

### Step 2: Detect WAF with wafw00f

```bash
TARGET_URL="https://example.com"

echo "=== wafw00f WAF detection ==="
wafw00f "$TARGET_URL" -a 2>&1
# -a : output all WAF candidates
```

### Step 3: Manual fingerprinting when wafw00f is unavailable

```bash
echo ""
echo "=== Manual WAF fingerprinting (curl) ==="

# 1) Collect baseline headers with a normal request
echo "--- Normal request ---"
NORMAL=$(curl -s -I "$TARGET_URL" --max-time 10 2>&1)
echo "$NORMAL" | grep -iE "server:|x-powered-by:|cf-ray:|x-amz|x-cache|x-cdn|via:|x-sucuri|x-fw-|x-waf"

# 2) Send a malicious payload to trigger WAF response
echo ""
echo "--- Payload request (checking WAF reaction) ---"
ATTACK=$(curl -s -o /dev/null -w "%{http_code}" \
  "$TARGET_URL/?q=<script>alert(1)</script>" \
  --max-time 10 2>&1)
echo "XSS payload HTTP status: $ATTACK"

SQLI=$(curl -s -o /dev/null -w "%{http_code}" \
  "$TARGET_URL/?id=1'+OR+'1'='1" \
  --max-time 10 2>&1)
echo "SQLi payload HTTP status: $SQLI"

HEADERS_ATTACK=$(curl -s -I \
  "$TARGET_URL/?q=<script>alert(1)</script>" \
  --max-time 10 2>&1)
echo ""
echo "--- Payload request response headers ---"
echo "$HEADERS_ATTACK" | grep -iE "server:|cf-ray:|x-amz|x-cache|x-sucuri|x-iinfo:|x-check-cacheable:|x-fw-|set-cookie:"
```

### Step 4: Compare against known WAF fingerprint patterns

```bash
echo ""
echo "=== WAF fingerprint pattern reference ==="
cat <<'EOF'
Cloudflare
  Headers: CF-RAY, Server: cloudflare
  Block response: 403/503 + "Cloudflare" in body, "__cf_bm" cookie

AWS WAF
  Headers: x-amzn-requestid, x-amz-cf-id
  Block response: 403 + "AWS" or "Request blocked"

Akamai
  Headers: X-Check-Cacheable, X-Akamai-*, Server: AkamaiGHost
  Block response: 403 + Reference #

F5 BIG-IP ASM
  Headers: X-WA-Info, Set-Cookie: TS (cookie starting with TS)
  Block response: policy block page

Sucuri
  Headers: X-Sucuri-ID, Server: Sucuri/Cloudproxy
  Block response: 403 + Sucuri logo page

ModSecurity (open source)
  Headers: mod_security in Server header or no special header
  Block response: 403 + "ModSecurity" in body or custom error page
EOF

echo ""
echo "=== Detection summary ==="
echo "Normal response code: $(echo "$NORMAL" | grep "^HTTP" | awk '{print $2}')"
echo "XSS payload blocked: $ATTACK"
echo "SQLi payload blocked: $SQLI"
```

## Done when

- WAF presence is determined (present / absent / inconclusive)
- WAF product name is identified where possible
- HTTP status code difference between normal and payload requests is recorded

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| wafw00f installation fails | pip permission issue. Use `pip install --user wafw00f` or a virtual environment |
| All payloads return 200 | No WAF present or detection is being evaded. Try URL-encoded payload variants |
| 403 returned but no WAF headers | May be application-level blocking. Check the response body |
| IP blocked due to rate limiting | Throttle requests by adding `sleep 2` between calls |

## Notes

- wafw00f can identify more than 140 WAFs (https://github.com/EnableSecurity/wafw00f).
- `identYwaf` (https://github.com/stamparm/identYwaf) is also useful for WAF bypass research.
- A "No WAF detected" result does not guarantee the absence of a WAF. Stealth-mode WAFs can evade detection.
