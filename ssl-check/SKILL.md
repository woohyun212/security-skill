---
name: ssl-check
description: Inspect SSL/TLS certificate validity, protocol versions, and cipher suites for a target host
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Performs a comprehensive SSL/TLS inspection of the target host using `openssl s_client` and `curl`. Checks certificate expiry date, issuer, and SAN (Subject Alternative Name), verifies whether deprecated protocol versions are disabled (TLS 1.0/1.1), lists cipher suites, and validates the certificate chain.

## When to use

- To quickly assess the security level of a server's TLS configuration
- To debug connection errors caused by certificate expiry or incorrect SAN
- During bug bounty or penetration testing to check for downgrade attack potential

## Prerequisites

- `openssl` installed (included by default on most Linux/macOS systems)
- `curl` installed
- Network access to port 443 (or specified port) on the target host

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `HOST` | Target hostname | `example.com` |
| `PORT` | TLS port (default 443) | `443` |

## Workflow

### Step 1: Collect certificate information

```bash
HOST="example.com"
PORT="443"

echo "=== Certificate Information ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | openssl x509 -noout \
  -subject -issuer -dates -fingerprint -ext subjectAltName

echo ""
echo "=== Days until certificate expiry ==="
EXPIRY=$(echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | openssl x509 -noout -enddate 2>/dev/null \
  | cut -d= -f2)

if [ -n "$EXPIRY" ]; then
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
  if [ "$DAYS_LEFT" -lt 30 ]; then
    echo "[WARNING] Certificate expiring soon: ${DAYS_LEFT} days remaining (expires: $EXPIRY)"
  else
    echo "[OK] Certificate valid: ${DAYS_LEFT} days remaining (expires: $EXPIRY)"
  fi
fi
```

### Step 2: Test protocol version support

```bash
echo ""
echo "=== Protocol Support ==="

test_protocol() {
  local proto="$1"
  local flag="$2"
  result=$(echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    "$flag" 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "[ENABLED]  $proto  <- active"
  else
    echo "[DISABLED] $proto"
  fi
}

test_protocol "TLS 1.0" "-tls1"
test_protocol "TLS 1.1" "-tls1_1"
test_protocol "TLS 1.2" "-tls1_2"
test_protocol "TLS 1.3" "-tls1_3"

echo ""
echo "Note: TLS 1.0 and 1.1 should show [DISABLED] for a secure configuration."
```

### Step 3: Check negotiated cipher suites

```bash
echo ""
echo "=== Negotiated Cipher Suite ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | grep "Cipher is"

echo ""
echo "=== Server cipher suite list (use nmap as alternative if needed) ==="
# Check known weak suites using openssl ciphers
WEAK_CIPHERS="RC4:DES:3DES:MD5:NULL:EXPORT:aNULL:eNULL"
echo "Testing weak cipher suites..."
for cipher in $(openssl ciphers "$WEAK_CIPHERS" 2>/dev/null | tr ':' ' '); do
  result=$(echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    -cipher "$cipher" 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "[WEAK CIPHER ACCEPTED] $cipher"
  fi
done
echo "Weak cipher suite test complete"
```

### Step 4: Certificate chain validation

```bash
echo ""
echo "=== Certificate Chain Validation ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | grep -E "verify return|Verify return code|Certificate chain"

echo ""
echo "=== Comprehensive TLS validation via curl ==="
curl -sv --max-time 10 "https://${HOST}/" 2>&1 \
  | grep -E "SSL connection|TLSv|cipher|issuer|expire|subject|verify"
```

## Done when

- Certificate expiry date and days remaining are printed
- Enabled/disabled status for TLS 1.0/1.1/1.2/1.3 is determined
- Negotiated cipher suite is displayed and acceptance of known weak suites is verified
- Certificate chain validation result (verify return code) is printed

## Failure modes

| Symptom | Cause and Resolution |
|---------|---------------------|
| `connect: Connection refused` | Port is closed. Check the PORT variable |
| `verify error:num=18:self signed certificate` | Self-signed certificate. A CA-signed certificate is required unless intentional |
| TLS 1.3 test fails | System openssl version does not support 1.3. Check with `openssl version` |
| Weak cipher suite test is slow | Add a timeout: `timeout 3 openssl s_client ...` |

## Notes

- For more detailed analysis, use `testssl.sh` (https://testssl.sh).
- Servers that do not support SNI require testing without the `-servername` flag.
- For STARTTLS services on ports 25/587/143 etc., add the appropriate flag such as `-starttls smtp`.
