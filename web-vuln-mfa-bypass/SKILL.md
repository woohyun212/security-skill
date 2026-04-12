---
name: web-vuln-mfa-bypass
description: Multi-factor authentication bypass techniques and detection
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Systematically tests Multi-Factor Authentication (MFA) implementations for bypass vulnerabilities including missing rate limiting, OTP reuse, response manipulation, race conditions on OTP submission, direct navigation to post-MFA pages, backup code handling flaws, MFA disable without re-verification, session fixation pre-MFA, predictable OTP values, and client-side MFA state storage.

## When to use

- When auditing a web application's MFA or 2FA implementation
- When testing TOTP, SMS OTP, email OTP, or push-notification based MFA flows
- When verifying whether MFA can be bypassed to gain unauthorized account access
- When evaluating backup code security or account recovery flows for MFA-enrolled users

## Prerequisites

- `curl` must be installed
- `parallel` (GNU parallel) must be installed for race condition tests: `apt install parallel`
- Valid test account with MFA enrolled
- Knowledge of the application's MFA verification endpoint and parameter names

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `BASE_URL` | Base URL of the application | `https://app.example.com` |
| `MFA_ENDPOINT` | Endpoint that accepts OTP submission | `/api/auth/mfa/verify` |
| `POST_MFA_PAGE` | Page only accessible after successful MFA | `/dashboard` |
| `SESSION_COOKIE` | Session cookie value after username/password login (pre-MFA state) | `session=abc123` |
| `KNOWN_OTP` | Valid OTP obtained via authenticator app (for reuse test) | `123456` |
| `MFA_PARAM` | POST parameter name for OTP value | `code` |

## Workflow

### Step 1: Map the MFA flow

```bash
BASE_URL="https://app.example.com"
MFA_ENDPOINT="/api/auth/mfa/verify"
POST_MFA_PAGE="/dashboard"
SESSION_COOKIE="session=abc123"
KNOWN_OTP="123456"
MFA_PARAM="code"

FULL_MFA_URL="${BASE_URL}${MFA_ENDPOINT}"
FULL_POST_MFA="${BASE_URL}${POST_MFA_PAGE}"

echo "=== Step 1: Map MFA flow ==="
echo "[+] MFA verification endpoint: $FULL_MFA_URL"
echo "[+] Post-MFA page: $FULL_POST_MFA"

# Check what parameters the MFA endpoint accepts
echo ""
echo "--- OPTIONS probe ---"
curl -s -X OPTIONS "$FULL_MFA_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  --max-time 10 \
  -D - -o /dev/null \
  | grep -iE "^(HTTP|Allow|Content-Type):"

# Baseline: submit obviously wrong OTP
echo ""
echo "--- Baseline (wrong OTP: 000000) ---"
curl -s -X POST "$FULL_MFA_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  --data "{\"${MFA_PARAM}\": \"000000\"}" \
  --max-time 10
echo ""
```

### Step 2: Test rate limiting on OTP verification

```bash
echo ""
echo "=== Step 2: Rate limiting test ==="
echo "[+] Submitting 20 incorrect OTPs in rapid succession..."

LOCKOUT_DETECTED=0
for i in $(seq 1 20); do
  CODE=$(printf "%06d" $((RANDOM % 1000000)))
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$FULL_MFA_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Content-Type: application/json" \
    --data "{\"${MFA_PARAM}\": \"$CODE\"}" \
    --max-time 10)
  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  BODY=$(echo "$RESPONSE" | head -1)

  if echo "$BODY" | grep -qiE "locked|blocked|too many|rate.?limit|throttl"; then
    echo "  [OK] Attempt $i: Rate limiting triggered ($HTTP_CODE) -> PASS"
    LOCKOUT_DETECTED=1
    break
  fi
  if [ "$i" -eq 20 ] && [ "$LOCKOUT_DETECTED" -eq 0 ]; then
    echo "  [FAIL] 20 attempts completed without lockout -> NO RATE LIMITING"
  fi
done
```

### Step 3: Test OTP reuse

```bash
echo ""
echo "=== Step 3: OTP reuse test ==="
echo "[!] Requires a recently-used valid OTP stored in KNOWN_OTP."

if [ "$KNOWN_OTP" != "123456" ]; then
  echo "[+] First use of OTP $KNOWN_OTP..."
  RESP1=$(curl -s -X POST "$FULL_MFA_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Content-Type: application/json" \
    --data "{\"${MFA_PARAM}\": \"$KNOWN_OTP\"}" \
    --max-time 10 -c /tmp/mfa_cookies1.txt)
  echo "  Response 1: $RESP1" | head -c 200

  echo ""
  echo "[+] Second use of same OTP $KNOWN_OTP (should be rejected)..."
  RESP2=$(curl -s -X POST "$FULL_MFA_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Content-Type: application/json" \
    --data "{\"${MFA_PARAM}\": \"$KNOWN_OTP\"}" \
    --max-time 10)
  echo "  Response 2: $RESP2" | head -c 200

  if echo "$RESP2" | grep -qiE "success|true|token|redirect|dashboard"; then
    echo ""
    echo "  [FAIL] Same OTP accepted twice -> OTP REUSE VULNERABILITY"
  else
    echo ""
    echo "  [OK] Second use rejected -> OTP reuse protection working"
  fi
else
  echo "  [SKIP] Set KNOWN_OTP to a real used OTP to run this test."
fi
```

### Step 4: Test response manipulation

```bash
echo ""
echo "=== Step 4: Response manipulation ==="
echo "[!] This test is most effective via a proxy (Burp Suite)."
echo "    The following demonstrates what to look for in the response:"
echo ""

echo "--- Submit incorrect OTP and capture full response ---"
curl -s -X POST "$FULL_MFA_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  --data "{\"${MFA_PARAM}\": \"999999\"}" \
  --max-time 10 \
  -v 2>&1 | grep -E "(^[<>]|success|status|result|error|false|true)"

echo ""
echo "[Manual check] Look for:"
echo "  - JSON response with 'success': false -> intercept and change to true"
echo "  - 'status': 'failure' -> change to 'success'"
echo "  - HTTP 401 -> intercept and change to 200"
echo "  - Redirect to /mfa-failed -> intercept and change to /dashboard"
echo "  Use Burp Suite Repeater or match-and-replace rules for this test."
```

### Step 5: Test direct navigation to post-MFA page

```bash
echo ""
echo "=== Step 5: Direct page access (MFA skip) ==="
echo "[+] Attempting to access post-MFA page with only pre-MFA session cookie..."

RESP=$(curl -s -w "\n%{http_code}" "$FULL_POST_MFA" \
  -H "Cookie: $SESSION_COOKIE" \
  --max-time 10 \
  -L)
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)

echo "  HTTP status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  if echo "$BODY" | grep -qiE "dashboard|welcome|account|profile|logout"; then
    echo "  [FAIL] Authenticated content returned without MFA -> MFA BYPASS via direct navigation"
  else
    echo "  [INFO] 200 returned but content appears generic; verify manually"
  fi
elif echo "$HTTP_CODE" | grep -qE "^(301|302|303)"; then
  LOCATION=$(curl -s -D - "$FULL_POST_MFA" \
    -H "Cookie: $SESSION_COOKIE" --max-time 10 | grep -i "^location:" | head -1)
  if echo "$LOCATION" | grep -qiE "mfa|login|2fa|verify"; then
    echo "  [OK] Redirected to MFA/login -> direct access blocked"
  else
    echo "  [WARN] Redirected to: $LOCATION -> verify destination manually"
  fi
else
  echo "  [OK] Access denied ($HTTP_CODE) -> MFA enforcement working"
fi
```

### Step 6: Test race condition on OTP submission

```bash
echo ""
echo "=== Step 6: Race condition test ==="
echo "[+] Submitting 10 parallel requests with valid OTP (requires GNU parallel)..."

if ! command -v parallel &>/dev/null; then
  echo "  [SKIP] GNU parallel not installed. Install with: apt install parallel"
else
  # Send 10 concurrent requests with the same OTP
  seq 1 10 | parallel -j10 "curl -s -X POST '$FULL_MFA_URL' \
    -H 'Cookie: $SESSION_COOKIE' \
    -H 'Content-Type: application/json' \
    --data '{\"${MFA_PARAM}\": \"$KNOWN_OTP\"}' \
    --max-time 10" \
  | grep -cE "success|token|dashboard"

  echo ""
  echo "  [Analysis] If multiple 'success' responses returned -> race condition allows"
  echo "  parallel OTP use before server-side invalidation completes"
fi
```

### Step 7: Test backup code handling

```bash
echo ""
echo "=== Step 7: Backup code brute force ==="
echo "[+] Testing backup code space (typically 8-10 digit codes, 8-10 codes per account)..."

BACKUP_CODES_TRIED=0
BACKUP_LOCKOUT=0

for code in 00000000 11111111 12345678 87654321 00000001; do
  RESP=$(curl -s -w "\n%{http_code}" -X POST "$FULL_MFA_URL" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Content-Type: application/json" \
    --data "{\"${MFA_PARAM}\": \"$code\", \"type\": \"backup\"}" \
    --max-time 10)
  HTTP_CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -1)
  BACKUP_CODES_TRIED=$((BACKUP_CODES_TRIED + 1))

  if echo "$BODY" | grep -qiE "locked|too many|rate.?limit"; then
    echo "  [OK] Backup code rate limiting triggered at attempt $BACKUP_CODES_TRIED"
    BACKUP_LOCKOUT=1
    break
  fi
done

if [ "$BACKUP_LOCKOUT" -eq 0 ]; then
  echo "  [WARN] No lockout after $BACKUP_CODES_TRIED backup code attempts -> verify rate limiting on backup codes"
fi
```

### Step 8: Test MFA disable flow

```bash
echo ""
echo "=== Step 8: MFA disable without re-verification ==="
echo "[+] Attempting to disable MFA without providing current OTP or password..."

# Common MFA disable endpoints
for endpoint in "/api/auth/mfa/disable" "/api/user/mfa" "/account/security/2fa/disable" "/api/2fa/remove"; do
  RESP=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}${endpoint}" \
    -H "Cookie: $SESSION_COOKIE" \
    -H "Content-Type: application/json" \
    --data '{"action": "disable"}' \
    --max-time 10)
  HTTP_CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -1)

  if [ "$HTTP_CODE" != "404" ]; then
    echo "  Found endpoint: ${BASE_URL}${endpoint} (HTTP $HTTP_CODE)"
    if echo "$BODY" | grep -qiE "disabled|removed|success|true"; then
      echo "  [FAIL] MFA disabled without re-verification -> VULNERABILITY"
    else
      echo "  [OK] Request rejected -> re-verification likely required"
    fi
  fi
done
```

### Step 9: Check client-side MFA state storage

```bash
echo ""
echo "=== Step 9: Client-side MFA state ==="
echo "[+] Checking for MFA status in cookies and localStorage-like responses..."

# Check cookies for MFA-related flags
curl -s "$BASE_URL/login" \
  --max-time 10 \
  -c /tmp/mfa_cookies_check.txt \
  -D - \
  -o /dev/null \
  | grep -i "^Set-Cookie:" | while IFS= read -r cookie; do
    echo "  Cookie: $cookie"
    if echo "$cookie" | grep -qiE "mfa|2fa|totp|otp|verified"; then
      echo "  [WARN] MFA-related cookie found -> check if value can be forged"
      if echo "$cookie" | grep -qiE "HttpOnly" ; then
        echo "  [OK] HttpOnly set"
      else
        echo "  [WARN] HttpOnly NOT set -> cookie accessible via JavaScript"
      fi
    fi
  done

echo ""
echo "[Manual check] Open browser DevTools -> Application -> Local Storage"
echo "  Look for keys containing: mfa, 2fa, verified, authenticated, step"
echo "  If MFA state stored client-side without server-side validation -> set to true/bypass"
```

### Step 10: Document bypass and impact

```bash
echo ""
echo "=== Step 10: Summary ==="
cat <<'EOF'
Severity guide:
  [CRITICAL] Direct page navigation bypasses MFA -> complete authentication bypass
  [CRITICAL] Response manipulation accepted by server -> MFA bypass for any account
  [HIGH]     No rate limiting on OTP -> brute force of 6-digit TOTP feasible (1,000,000 combinations)
  [HIGH]     OTP reuse allowed -> stolen OTP valid multiple times
  [HIGH]     Race condition -> concurrent requests allow OTP use before invalidation
  [HIGH]     MFA can be disabled without re-verification -> social engineering + MFA removal
  [MEDIUM]   Backup codes not rate-limited -> slow brute force possible
  [MEDIUM]   MFA state stored in client-side cookie without integrity check
  [LOW]      Predictable/default OTP values accepted

Remediation:
  - Enforce server-side rate limiting (5-10 attempts max) with exponential backoff on OTP endpoint
  - Invalidate OTP immediately upon first use; reject replay within the same TOTP window
  - Validate MFA completion server-side before granting access to any post-MFA resource
  - Use optimistic locking or atomic server-side state transitions to prevent race conditions
  - Require current password or valid OTP before allowing MFA disable/change
  - Never store MFA state in client-side cookies or localStorage
  - Apply same rate limiting to backup codes as to primary OTP
EOF
```

## Done when

- MFA flow is mapped and baseline incorrect-OTP response is captured
- Rate limiting is tested with at least 20 sequential attempts
- OTP reuse is tested with a known valid code
- Direct page access is attempted with pre-MFA session cookie
- Race condition test is executed (if GNU parallel available)
- Backup code brute force resistance is spot-checked
- MFA disable endpoint is probed without re-verification
- Client-side cookies are inspected for MFA state flags
- All findings are classified by severity

## Failure modes

| Symptom | Cause | Solution |
|---------|-------|----------|
| All requests return 401 immediately | Pre-MFA session cookie expired or invalid | Re-authenticate to obtain a fresh pre-MFA session cookie |
| Rate limiting triggers after just 3 attempts | Aggressive lockout policy | Note as finding context; reduce test rate to avoid locking test account |
| `parallel` command not found | GNU parallel not installed | `sudo apt install parallel` or manually run concurrent curl commands in background with `&` |
| MFA endpoint returns 404 for all variants | Endpoint path is non-standard | Use browser DevTools Network tab to capture the actual MFA submission URL |
| Response manipulation test inconclusive | Server validates response integrity | This is expected for well-implemented MFA; document as pass |

## Notes

- Always use dedicated test accounts for MFA bypass testing; repeated failed OTP attempts may lock legitimate user accounts.
- TOTP brute force is theoretically possible without rate limiting (1,000,000 combinations for 6-digit codes) but each code is valid for only 30 seconds — rate limiting is the primary defense.
- The race condition technique is documented in detail by James Kettle: concurrent requests exploit the window between OTP validation and invalidation.
- For SMS-based OTP, also test SIM-swap and SS7 attack scenarios as separate higher-level threat vectors.
- Reference: PortSwigger MFA lab — https://portswigger.net/web-security/authentication/multi-factor
