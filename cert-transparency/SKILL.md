---
name: cert-transparency
description: Certificate Transparency log search via crt.sh API to discover subdomains and certificates
license: MIT
metadata:
  category: recon
  locale: en
  phase: recon
---

## What this skill does

Queries TLS/SSL certificates issued for a specific domain via the crt.sh Certificate Transparency (CT) log API. Extracts subdomains from the CN (Common Name) and SAN (Subject Alternative Name) fields of certificates, deduplicates them, and expands the attack surface.

## When to use

- Enumerating subdomains passively (no DNS queries)
- Discovering subdomains covered by wildcard certificates
- Auditing the list of certificates issued by a specific organization
- Supplementing subfinder/amass results with an additional source

## Prerequisites

- Install `curl`:
  ```bash
  sudo apt-get install -y curl
  ```
- Install `jq` (JSON parsing):
  ```bash
  sudo apt-get install -y jq
  ```
- External internet access required (crt.sh API calls)
- Environment variable `SECSKILL_TARGET_DOMAIN`: domain to query

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET_DOMAIN` | Required | Root domain to query (e.g. `example.com`) |
| `SECSKILL_OUTPUT_DIR` | Optional | Output directory for results (default: `./output`) |
| `SECSKILL_INCLUDE_EXPIRED` | Optional | Set to `true` to include expired certificates (default: `false`) |

## Workflow

### Step 1: Prepare environment

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?Set the SECSKILL_TARGET_DOMAIN environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export INCLUDE_EXPIRED="${SECSKILL_INCLUDE_EXPIRED:-false}"
mkdir -p "$OUTDIR"
echo "[*] Starting Certificate Transparency lookup: $TARGET"
```

### Step 2: Query crt.sh API

```bash
echo "[*] Querying crt.sh API..."
CRT_URL="https://crt.sh/?q=%.${TARGET}&output=json"

RAW_JSON="$OUTDIR/crt_raw_${TARGET}.json"

HTTP_CODE=$(curl -s -o "$RAW_JSON" -w "%{http_code}" \
  --max-time 30 \
  --retry 3 \
  --retry-delay 5 \
  "$CRT_URL")

if [ "$HTTP_CODE" != "200" ]; then
  echo "[-] crt.sh API error (HTTP $HTTP_CODE). Please retry after a moment."
  exit 1
fi

CERT_COUNT=$(jq 'length' "$RAW_JSON" 2>/dev/null || echo "0")
echo "[+] Certificates found: $CERT_COUNT"
```

### Step 3: Extract subdomains and deduplicate

```bash
echo "[*] Extracting subdomains..."
SUBDOMAINS_FILE="$OUTDIR/ct_subdomains_${TARGET}.txt"

jq -r '.[].name_value' "$RAW_JSON" 2>/dev/null \
  | tr ',' '\n' \
  | sed 's/^\*\.//' \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E "\\.${TARGET}$|^${TARGET}$" \
  | sort -u \
  > "$SUBDOMAINS_FILE"

SUB_COUNT=$(wc -l < "$SUBDOMAINS_FILE")
echo "[+] Unique subdomains: $SUB_COUNT"
```

### Step 4: Filter to non-expired certificates only (optional)

```bash
if [ "$INCLUDE_EXPIRED" != "true" ]; then
  echo "[*] Extracting subdomains from valid certificates only..."
  VALID_SUBDOMAINS_FILE="$OUTDIR/ct_valid_subdomains_${TARGET}.txt"

  NOW=$(date -u '+%Y-%m-%dT%H:%M:%S')
  jq -r --arg now "$NOW" \
    '.[] | select(.not_after > $now) | .name_value' "$RAW_JSON" 2>/dev/null \
    | tr ',' '\n' \
    | sed 's/^\*\.//' \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E "\\.${TARGET}$|^${TARGET}$" \
    | sort -u \
    > "$VALID_SUBDOMAINS_FILE"

  VALID_COUNT=$(wc -l < "$VALID_SUBDOMAINS_FILE")
  echo "[+] Subdomains from valid certificates: $VALID_COUNT"
fi
```

### Step 5: Certificate issuer statistics

```bash
echo ""
echo "===== Certificate Issuer Statistics ====="
jq -r '.[].issuer_name' "$RAW_JSON" 2>/dev/null \
  | grep -oP '(?<=O=)[^,]+' \
  | sort | uniq -c | sort -rn | head -10
echo "========================================="
```

### Step 6: Identify wildcard certificates

```bash
echo ""
echo "===== Wildcard Certificate List ====="
jq -r '.[].name_value' "$RAW_JSON" 2>/dev/null \
  | tr ',' '\n' \
  | grep '^\*\.' \
  | sort -u \
  | head -20
echo "======================================"
```

### Step 7: Results summary

```bash
echo ""
echo "===== Certificate Transparency Results Summary ====="
echo "Target domain    : $TARGET"
echo "Certificates found: $CERT_COUNT"
echo "Unique subdomains: $SUB_COUNT"
echo "Output file      : $SUBDOMAINS_FILE"
echo "Raw JSON         : $RAW_JSON"
echo "==================================================="
```

## Done when

- crt.sh API response is HTTP 200
- Subdomain list file is created
- Extracted subdomain count is printed

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| HTTP 503 error | crt.sh server overload | Retry after a few minutes |
| `jq: command not found` | jq not installed | Run `apt-get install jq` |
| 0 results | New domain or not submitted to CT | Verify domain, use `subdomain-enum` skill in parallel |
| JSON parse error | API response format changed | Check raw response with `cat $RAW_JSON` |
| Timeout | Network latency | Increase `--max-time` value (60 seconds or more) |

## Notes

- CT logs are public data and require no authentication.
- Wildcard certificates (`*.example.com`) can cover thousands of subdomains.
- Expired certificates are also useful for understanding past infrastructure layout.
- Merging extracted subdomains with `subdomain-enum` skill results yields a more complete list.
- Censys (`https://censys.io`) and the Facebook CT API can be used as complementary sources alongside crt.sh.
