---
name: cors-check
description: Detect CORS misconfiguration by testing various Origin headers and analyzing Access-Control responses
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Sends HTTP requests with various `Origin` header values to a target URL to detect vulnerabilities in CORS (Cross-Origin Resource Sharing) policy. Identifies misconfigurations such as `Access-Control-Allow-Origin` reflecting the request Origin verbatim, allowing `null`, or simultaneously setting `*` with `Access-Control-Allow-Credentials: true`.

## When to use

- When auditing the CORS policy of an API endpoint
- When checking for Cross-Site Request Forgery (CSRF) or credential theft possibilities
- When validating CORS-based account takeover vulnerabilities in bug bounty programs

## Prerequisites

- `curl` must be installed
- HTTP/HTTPS access to the target URL

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Endpoint URL to test | `https://api.example.com/user` |
| `LEGITIMATE_ORIGIN` | Known legitimate origin (if available) | `https://example.com` |

## Workflow

### Step 1: Check baseline CORS response

```bash
TARGET_URL="https://api.example.com/user"
LEGITIMATE_ORIGIN="https://example.com"

echo "=== Baseline CORS headers (no Origin) ==="
curl -s -I -X GET "$TARGET_URL" \
  --max-time 10 2>&1 \
  | grep -i "access-control"
```

### Step 2: Test reflection with various Origin values

```bash
echo ""
echo "=== Origin reflection test ==="

test_cors() {
  local label="$1"
  local origin="$2"
  local response
  response=$(curl -s -I -X GET "$TARGET_URL" \
    -H "Origin: $origin" \
    --max-time 10 2>&1)

  local acao
  acao=$(echo "$response" | grep -i "access-control-allow-origin:" | tr -d '\r')
  local acac
  acac=$(echo "$response" | grep -i "access-control-allow-credentials:" | tr -d '\r')

  echo "--- [$label] Origin: $origin ---"
  echo "  ACAO: ${acao:-<none>}"
  echo "  ACAC: ${acac:-<none>}"

  # Risk assessment
  if echo "$acao" | grep -qi "$origin"; then
    if echo "$acac" | grep -qi "true"; then
      echo "  [CRITICAL] Origin reflected + Credentials=true -> credential theft possible"
    else
      echo "  [WARNING]  Origin reflected (no Credentials)"
    fi
  fi
  if echo "$acao" | grep -q '^\s*[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:\s*\*'; then
    if echo "$acac" | grep -qi "true"; then
      echo "  [CRITICAL] ACAO=* + Credentials=true -> blocked by browser but still a misconfiguration"
    else
      echo "  [INFO]     ACAO=* (wildcard; acceptable for unauthenticated public APIs)"
    fi
  fi
  echo ""
}

test_cors "Legitimate origin"        "$LEGITIMATE_ORIGIN"
test_cors "null Origin"              "null"
test_cors "Attacker domain"          "https://attacker.com"
test_cors "Subdomain"                "https://sub.example.com"
test_cors "Prefix-similar domain"    "https://example.com.evil.com"
test_cors "Trailing slash variant"   "${LEGITIMATE_ORIGIN}/"
test_cors "HTTP downgrade"           "http://example.com"
```

### Step 3: Test Preflight (OPTIONS) request

```bash
echo "=== Preflight OPTIONS request test ==="
curl -s -I -X OPTIONS "$TARGET_URL" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \
  --max-time 10 2>&1 \
  | grep -i "access-control"
```

### Step 4: Summarize results and assess risk

```bash
echo ""
echo "=== Risk assessment criteria ==="
cat <<'EOF'
[CRITICAL]  ACAO reflects request Origin + ACAC: true
            -> Attacker can execute authenticated API requests cross-site

[HIGH]      ACAO: null + ACAC: true
            -> Exploitable from sandboxed iframes or local files

[MEDIUM]    ACAO reflects request Origin (no ACAC)
            -> Dangerous if the response contains sensitive data

[LOW/INFO]  ACAO: * (wildcard, no ACAC)
            -> May be intentional for public APIs

Remediation:
  - Fix allowed Origins to a whitelist (no dynamic reflection)
  - Do not use wildcard (*) when credentials=true
  - Disallow null Origin
  - Add Vary: Origin header (prevents cache poisoning)
EOF
```

## Done when

- ACAO/ACAC responses are printed for 8 or more Origin variants
- Dangerous configurations (reflection + Credentials, null Origin allowed, etc.) are automatically detected and flagged

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| No ACAO header on all tests | CORS policy not configured or same-origin only. curl responses may differ from browser behavior |
| 302 redirect preventing expected response | Add `-L` flag or specify the final URL directly |
| Server blocks OPTIONS method | 405 response means Preflight not supported. Fall back to simple request (GET/POST) testing |

## Notes

- Browsers block the `ACAO: * + ACAC: true` combination, but the server configuration is still wrong and should be reported.
- If a subdomain has XSS, allowing that subdomain as an Origin can also be a vulnerability.
- Automation tool: consider using `corsy` (https://github.com/s0md3v/Corsy).
