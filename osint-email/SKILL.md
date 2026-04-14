---
name: osint-email
description: Email-based OSINT collection including breach database checks and social account enumeration
license: MIT
metadata:
  category: recon
  locale: en
  phase: v1
---

## What this skill does

Collects OSINT information based on an email address. Performs email format validation, breach history lookup via the Have I Been Pwned API, and social/service account existence detection using holehe.

## When to use

- Checking an email's exposure history before phishing simulations
- Verifying whether employee emails were included in data breaches
- Assessing social engineering attack potential
- Auditing the digital footprint of an individual or organization

## Prerequisites

- Install `curl`
- Install holehe (social account checking):
  ```bash
  pip install holehe
  ```
- Obtain a Have I Been Pwned API key: https://haveibeenpwned.com/API/Key
- Set environment variables:
  - `SECSKILL_TARGET_EMAIL`: email address to query
  - `SECSKILL_HIBP_API_KEY`: Have I Been Pwned API key

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET_EMAIL` | Required | Email address to query |
| `SECSKILL_HIBP_API_KEY` | Required | HIBP API key (for breach history lookup) |
| `SECSKILL_OUTPUT_DIR` | Optional | Output directory for results (default: `./output`) |
| `SECSKILL_RUN_HOLEHE` | Optional | Set to `true` to run holehe (default: `false`) |

## Workflow

### Step 1: Email format validation

```bash
export EMAIL="${SECSKILL_TARGET_EMAIL:?Set the SECSKILL_TARGET_EMAIL environment variable}"
export HIBP_KEY="${SECSKILL_HIBP_API_KEY:-}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export RUN_HOLEHE="${SECSKILL_RUN_HOLEHE:-false}"
mkdir -p "$OUTDIR"

SAFE_EMAIL=$(echo "$EMAIL" | tr '@.' '__')
OUTFILE="$OUTDIR/osint_email_${SAFE_EMAIL}.txt"

echo "===== Email OSINT: $EMAIL =====" > "$OUTFILE"
echo "Query time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"

# Format validation
if echo "$EMAIL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
  echo "[+] Valid email format: $EMAIL" | tee -a "$OUTFILE"
  DOMAIN=$(echo "$EMAIL" | cut -d'@' -f2)
  USER=$(echo "$EMAIL" | cut -d'@' -f1)
  echo "[*] Domain: $DOMAIN | User: $USER"
else
  echo "[-] Invalid email format: $EMAIL"
  exit 1
fi
```

### Step 2: Have I Been Pwned - breach history check

```bash
echo "" >> "$OUTFILE"
echo "--- Have I Been Pwned Breach History ---" | tee -a "$OUTFILE"

if [ -z "$HIBP_KEY" ]; then
  echo "[-] SECSKILL_HIBP_API_KEY not set. Skipping HIBP check." | tee -a "$OUTFILE"
else
  ENCODED_EMAIL=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$EMAIL'))")
  HIBP_RESPONSE=$(curl -s \
    -H "hibp-api-key: $HIBP_KEY" \
    -H "user-agent: SecuritySkill-OSINT/1.0" \
    --max-time 15 \
    "https://haveibeenpwned.com/api/v3/breachedaccount/${ENCODED_EMAIL}?truncateResponse=false")

  HTTP_STATUS=$?
  if echo "$HIBP_RESPONSE" | grep -q '"Name"'; then
    BREACH_COUNT=$(echo "$HIBP_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))")
    echo "[!] Breaches found: $BREACH_COUNT" | tee -a "$OUTFILE"
    echo "$HIBP_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for breach in data:
    print(f\"  - {breach['Name']} ({breach['BreachDate']}): {', '.join(breach['DataClasses'][:5])}\")
" | tee -a "$OUTFILE"
  elif echo "$HIBP_RESPONSE" | grep -q "404"; then
    echo "[+] No breach history (not found in database)" | tee -a "$OUTFILE"
  else
    echo "[-] HIBP API response error. Check your API key or network." | tee -a "$OUTFILE"
  fi
fi
```

### Step 3: Have I Been Pwned - paste check

```bash
if [ -n "$HIBP_KEY" ]; then
  echo "" >> "$OUTFILE"
  echo "--- Paste Database Check ---" | tee -a "$OUTFILE"

  ENCODED_EMAIL=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$EMAIL'))")
  PASTE_RESPONSE=$(curl -s \
    -H "hibp-api-key: $HIBP_KEY" \
    -H "user-agent: SecuritySkill-OSINT/1.0" \
    --max-time 15 \
    "https://haveibeenpwned.com/api/v3/pasteaccount/${ENCODED_EMAIL}")

  if echo "$PASTE_RESPONSE" | grep -q '"Source"'; then
    PASTE_COUNT=$(echo "$PASTE_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))")
    echo "[!] Paste site exposures: $PASTE_COUNT" | tee -a "$OUTFILE"
    echo "$PASTE_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for paste in data[:10]:
    print(f\"  - {paste['Source']}: {paste.get('Title','(no title)')} ({paste.get('Date','date unknown')})\")
" | tee -a "$OUTFILE"
  else
    echo "[+] No paste site exposures found" | tee -a "$OUTFILE"
  fi
fi
```

### Step 4: Email domain MX record check

```bash
echo "" >> "$OUTFILE"
echo "--- Email Domain DNS Check ---" | tee -a "$OUTFILE"

MX=$(dig "$DOMAIN" MX +short 2>/dev/null | sort)
if [ -n "$MX" ]; then
  echo "[+] MX records valid - email delivery is possible" | tee -a "$OUTFILE"
  echo "$MX" | tee -a "$OUTFILE"
else
  echo "[-] No MX records - email address may be invalid" | tee -a "$OUTFILE"
fi
```

### Step 5: Social account check with holehe (optional)

```bash
if [ "$RUN_HOLEHE" = "true" ]; then
  echo "" >> "$OUTFILE"
  echo "--- holehe Social Account Check ---" | tee -a "$OUTFILE"

  if command -v holehe >/dev/null 2>&1; then
    echo "[*] Running holehe (may take tens of seconds)..."
    holehe --only-used "$EMAIL" 2>/dev/null \
      | grep -E "^\[|\[\+\]|\[-\]" \
      | tee -a "$OUTFILE"
    echo "[+] holehe complete"
  else
    echo "[-] holehe not installed. Install with: pip install holehe" | tee -a "$OUTFILE"
  fi
else
  echo "[*] holehe skipped (enable with SECSKILL_RUN_HOLEHE=true)"
fi
```

### Step 6: Results summary

```bash
echo ""
echo "===== Email OSINT Results Summary ====="
echo "Target email: $EMAIL"
echo "Output file : $OUTFILE"
echo "======================================="
cat "$OUTFILE"
```

## Done when

- Email format validation is complete
- HIBP API call results are recorded (when key is provided)
- holehe results are recorded (when `SECSKILL_RUN_HOLEHE=true`)
- Output file is created

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| HIBP 401 error | Invalid API key | Re-verify key in HIBP dashboard |
| HIBP 429 error | Rate limit exceeded | Retry after 1 minute (API enforces 1.5-second intervals) |
| holehe error | Package dependency issue | Run `pip install --upgrade holehe` |
| No MX records | Invalid domain | Re-verify email address |

## Notes

- The HIBP API is paid ($3.50/month) but affordable for personal use.
- holehe checks account existence across 100+ services (no password attempts).
- Only use on yourself or targets with explicit consent.
- Store collected information securely and delete unnecessary personal data after reporting.
- Compliance with privacy laws such as GDPR and CCPA is required.
