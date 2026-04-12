---
name: cert-parse
description: Parse X.509 certificate details and verify certificate chain integrity
license: MIT
metadata:
  category: crypto
  locale: en
  phase: v1
---

## What this skill does

Accepts an X.509 certificate file or PEM text and uses `openssl x509` to parse the Subject, Issuer, SAN, validity period, public key info, and extension fields. If a CA bundle is provided, performs chain verification with `openssl verify`, and automatically checks for common issues such as weak keys, expiry, and self-signing.

## When to use

- Inspecting a server certificate before or after deployment
- Debugging certificate chain errors (e.g., UNABLE_TO_GET_ISSUER_CERT)
- Checking certificate-related vulnerabilities (weak keys, wildcard misuse, etc.) during bug bounty or penetration testing

## Prerequisites

- `openssl` installed (built into Linux/macOS)
- Certificate file (PEM/DER) or PEM text
- CA bundle file for chain verification (optional)

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `CERT_INPUT` | PEM file path or remote host | `/path/to/cert.pem` or `example.com:443` |
| `CA_BUNDLE` | (optional) CA bundle file path | `/etc/ssl/certs/ca-certificates.crt` |

## Workflow

### Step 1: Extract PEM from certificate source

```bash
CERT_INPUT="/path/to/cert.pem"  # or "example.com:443"
WORK_CERT="/tmp/target_cert.pem"

# Determine whether input is a file or host:port
if [ -f "$CERT_INPUT" ]; then
  echo "=== Loading certificate from file: $CERT_INPUT ==="
  # Auto-convert DER format to PEM
  if openssl x509 -in "$CERT_INPUT" -noout 2>/dev/null; then
    cp "$CERT_INPUT" "$WORK_CERT"
    echo "PEM format confirmed"
  else
    openssl x509 -in "$CERT_INPUT" -inform DER -out "$WORK_CERT" 2>/dev/null && \
      echo "DER -> PEM conversion complete" || echo "Certificate format parsing failed"
  fi
else
  echo "=== Fetching certificate from remote host: $CERT_INPUT ==="
  HOST=$(echo "$CERT_INPUT" | cut -d: -f1)
  PORT=$(echo "$CERT_INPUT" | cut -d: -f2)
  PORT=${PORT:-443}
  echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    2>/dev/null | openssl x509 -out "$WORK_CERT"
  echo "Remote certificate saved: $WORK_CERT"
fi
```

### Step 2: Parse key certificate fields

```bash
echo ""
echo "=== Certificate details ==="

echo "--- Subject ---"
openssl x509 -in "$WORK_CERT" -noout -subject

echo ""
echo "--- Issuer ---"
openssl x509 -in "$WORK_CERT" -noout -issuer

echo ""
echo "--- Validity period ---"
openssl x509 -in "$WORK_CERT" -noout -dates

echo ""
echo "--- Subject Alternative Names (SAN) ---"
openssl x509 -in "$WORK_CERT" -noout -ext subjectAltName 2>/dev/null \
  || openssl x509 -in "$WORK_CERT" -text -noout | grep -A3 "Subject Alternative Name"

echo ""
echo "--- Public key info ---"
openssl x509 -in "$WORK_CERT" -noout -pubkey | openssl pkey -pubin -noout -text 2>/dev/null \
  || openssl x509 -in "$WORK_CERT" -noout -text | grep -A3 "Public Key Algorithm"

echo ""
echo "--- Signature algorithm ---"
openssl x509 -in "$WORK_CERT" -noout -text | grep "Signature Algorithm" | head -2

echo ""
echo "--- Extensions ---"
openssl x509 -in "$WORK_CERT" -noout -text \
  | sed -n '/X509v3 extensions/,/Signature Algorithm/p' \
  | head -40
```

### Step 3: Automated security checks

```bash
echo ""
echo "=== Automated security checks ==="

# Check expiry
EXPIRY=$(openssl x509 -in "$WORK_CERT" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [ "$DAYS_LEFT" -lt 0 ]; then
  echo "[CRITICAL] Certificate expired (${DAYS_LEFT#-} days ago)"
elif [ "$DAYS_LEFT" -lt 30 ]; then
  echo "[WARNING]  Certificate expiring soon: ${DAYS_LEFT} days remaining"
else
  echo "[OK]       Certificate valid: ${DAYS_LEFT} days remaining"
fi

# Check for self-signed
SUBJECT=$(openssl x509 -in "$WORK_CERT" -noout -subject)
ISSUER=$(openssl x509 -in "$WORK_CERT" -noout -issuer)
if [ "$SUBJECT" = "$ISSUER" ]; then
  echo "[WARNING]  Self-signed certificate (Subject == Issuer)"
else
  echo "[OK]       CA-signed certificate"
fi

# Check key length
KEY_INFO=$(openssl x509 -in "$WORK_CERT" -noout -text 2>/dev/null | grep "Public-Key:")
KEY_BITS=$(echo "$KEY_INFO" | grep -oP '\(\K[0-9]+(?= bit)')
if [ -n "$KEY_BITS" ]; then
  if [ "$KEY_BITS" -lt 2048 ]; then
    echo "[CRITICAL] Weak RSA key: ${KEY_BITS} bits (minimum 2048 bits recommended)"
  elif [ "$KEY_BITS" -lt 4096 ]; then
    echo "[INFO]     RSA key: ${KEY_BITS} bits (acceptable, 4096 bits recommended)"
  else
    echo "[OK]       RSA key: ${KEY_BITS} bits"
  fi
fi

# Check MD5/SHA1 signature algorithm
SIG_ALG=$(openssl x509 -in "$WORK_CERT" -noout -text | grep "Signature Algorithm" | head -1)
if echo "$SIG_ALG" | grep -qi "md5\|sha1"; then
  echo "[CRITICAL] Weak signature algorithm: $SIG_ALG"
else
  echo "[OK]       Signature algorithm: $SIG_ALG"
fi

# Check for wildcard certificate
WILD=$(openssl x509 -in "$WORK_CERT" -noout -text | grep "\*\.")
if [ -n "$WILD" ]; then
  echo "[INFO]     Wildcard certificate detected: $WILD"
fi
```

### Step 4: Certificate chain verification (when CA bundle is provided)

```bash
CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"  # or custom CA bundle

echo ""
echo "=== Certificate chain verification ==="
if [ -f "$CA_BUNDLE" ]; then
  openssl verify -CAfile "$CA_BUNDLE" "$WORK_CERT" 2>&1
else
  echo "No CA bundle found. Attempting verification with system default CA..."
  openssl verify "$WORK_CERT" 2>&1
fi

echo ""
echo "=== Full certificate text output (optional) ==="
echo "To print full output, run:"
echo "  openssl x509 -in $WORK_CERT -text -noout"
```

## Done when

- Subject, Issuer, SAN, validity period, public key algorithm, and signature algorithm are all printed
- Automated checks for expiry, self-signing, weak keys, and weak signature algorithms are complete
- (When CA bundle is provided) Chain verification result (OK or error code) is printed

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| `unable to load certificate` | File format mismatch. If DER, add `-inform DER` |
| No SAN field | Legacy certificate using CN only. Modern browsers may reject certificates without SAN |
| Chain verification `unable to get local issuer certificate` | Intermediate CA certificate missing. Fetch the full chain from the server |
| Remote certificate fetch failure | Firewall or SNI issue. Check `-servername` flag and port |

## Notes

- To fetch the full chain including intermediate CAs: `openssl s_client -connect host:443 -showcerts`
- To extract the public key hash for certificate pinning verification: `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`
- To search CT (Certificate Transparency) logs: https://crt.sh/?q=example.com
