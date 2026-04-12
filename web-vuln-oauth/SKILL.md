---
name: web-vuln-oauth
description: OAuth 2.0 and OIDC vulnerability detection with redirect_uri bypass techniques
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Tests OAuth 2.0 and OpenID Connect implementations for misconfigurations that lead to account takeover (ATO). Covers 11 `redirect_uri` bypass techniques, missing PKCE enforcement, state parameter absence or fixation, authorization code theft via Referer leakage, scope escalation, implicit flow abuse, and token leakage in browser history.

## When to use

- When a target application has a "Login with ..." button (Google, GitHub, Facebook, or custom OAuth provider)
- When auditing first-party OAuth authorization servers
- When testing mobile or SPA clients that should enforce PKCE
- During bug bounty on any scope that includes authentication or SSO

## Prerequisites

- `curl` installed
- Burp Suite (recommended for intercepting and replaying authorization flows)
- Two test accounts on the target application
- The application's `client_id` and authorization endpoint (obtainable from page source or network traffic)

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `AUTH_ENDPOINT` | OAuth authorization endpoint | `https://auth.example.com/oauth2/authorize` |
| `TOKEN_ENDPOINT` | OAuth token endpoint | `https://auth.example.com/oauth2/token` |
| `CLIENT_ID` | OAuth client_id for the application | `abc123client` |
| `REDIRECT_URI` | Registered redirect_uri | `https://app.example.com/callback` |
| `SCOPE` | Requested scopes | `openid profile email` |

## Workflow

### Step 1: Identify OAuth endpoints

```bash
AUTH_ENDPOINT="https://auth.example.com/oauth2/authorize"
TOKEN_ENDPOINT="https://auth.example.com/oauth2/token"
CLIENT_ID="abc123client"
REDIRECT_URI="https://app.example.com/callback"
SCOPE="openid profile email"

# Check for OIDC discovery document (reveals all endpoints)
ISSUER="https://auth.example.com"
curl -s "$ISSUER/.well-known/openid-configuration" | python3 -m json.tool
curl -s "$ISSUER/.well-known/oauth-authorization-server" | python3 -m json.tool
```

### Step 2: Test redirect_uri bypass techniques

```bash
echo "=== Testing redirect_uri bypass techniques ==="

# Baseline: confirm the legitimate redirect works
BASELINE_URL="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")&scope=openid&state=teststate123"
echo "Baseline URL: $BASELINE_URL"
echo ""

test_redirect() {
  local label="$1"
  local uri="$2"
  local encoded
  encoded=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$uri")
  local url="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encoded}&scope=openid&state=teststate"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 "$url")
  echo "[$status] $label"
  echo "         $uri"
  echo ""
}

# 1. Open redirect on registered domain
test_redirect "Open redirect (path traversal)"        "https://app.example.com/callback/../../../redirect?url=https://attacker.com"

# 2. Subdomain of registered domain
test_redirect "Subdomain match"                       "https://evil.app.example.com/callback"

# 3. Registered domain as URL parameter
test_redirect "Domain as parameter"                   "https://attacker.com/?app.example.com"

# 4. Fragment abuse
test_redirect "Fragment bypass"                       "https://attacker.com#app.example.com/callback"

# 5. Parameter pollution (duplicate redirect_uri)
echo "[MANUAL] Parameter pollution:"
echo "  ${AUTH_ENDPOINT}?...&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('https://attacker.com'))")"
echo ""

# 6. URL encoding
test_redirect "URL encoding (%2F)"                    "https://app.example.com%2Fattacker.com"

# 7. IDN homograph (Cyrillic/Unicode lookalike)
test_redirect "IDN homograph"                         "https://аpp.example.com/callback"

# 8. Double encoding
test_redirect "Double encoding (%252F)"               "https://app.example.com%252F%252Fattacker.com"

# 9. Backslash normalization
test_redirect "Backslash normalization"               "https://app.example.com\@attacker.com/callback"

# 10. Localhost variants
test_redirect "Localhost variant"                     "https://localhost.attacker.com/callback"

# 11. Scheme confusion
test_redirect "Scheme confusion (javascript:)"        "javascript:alert(document.domain)"
```

### Step 3: Check PKCE enforcement for mobile/SPA clients

```bash
echo "=== Testing PKCE enforcement ==="

# Send authorization request WITHOUT code_challenge
# A properly configured server must reject this for public clients
NO_PKCE_URL="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")&scope=openid&state=pkcetest"

STATUS=$(curl -s -o /tmp/pkce_response.txt -w "%{http_code}" -L --max-time 10 "$NO_PKCE_URL")
echo "Response without code_challenge: HTTP $STATUS"
cat /tmp/pkce_response.txt

if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
  echo "[POTENTIAL ISSUE] Server did not reject missing PKCE — check if this is a public client"
  echo "                  Auth code interception attack may be possible"
else
  echo "[OK] Server rejected request without PKCE"
fi
```

### Step 4: Test state parameter (CSRF on OAuth)

```bash
echo ""
echo "=== Testing state parameter ==="

# 1. Missing state parameter
NO_STATE_URL="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")&scope=openid"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$NO_STATE_URL")
echo "Request without state: HTTP $STATUS"

# 2. Empty state parameter
EMPTY_STATE_URL="${NO_STATE_URL}&state="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$EMPTY_STATE_URL")
echo "Request with empty state: HTTP $STATUS"

echo ""
echo "[MANUAL] State fixation test:"
echo "  1. Start OAuth flow as attacker, capture the authorization URL with state=ATTACKER_STATE"
echo "  2. Send that URL to the victim without completing authorization"
echo "  3. Victim clicks the link and authorizes"
echo "  4. Check if the victim's authorization code is now tied to the attacker's session"
```

### Step 5: Test authorization code theft via Referer

```bash
echo ""
echo "=== Checking for auth code in Referer leakage ==="
echo "[MANUAL] After completing a login flow:"
echo "  1. Observe the callback URL: $REDIRECT_URI?code=AUTH_CODE&state=..."
echo "  2. Check if the callback page loads third-party scripts (analytics, ads, fonts)"
echo "  3. If yes, the browser sends: Referer: $REDIRECT_URI?code=AUTH_CODE to each third party"
echo "  4. Auth code in Referer = theft possible even without redirect_uri bypass"
```

### Step 6: Check token handling and implicit flow

```bash
echo ""
echo "=== Implicit flow and token leakage check ==="

# Implicit flow puts access_token in URL fragment → browser history
IMPLICIT_URL="${AUTH_ENDPOINT}?response_type=token&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI'))")&scope=openid&state=implicittest"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$IMPLICIT_URL")
echo "Implicit flow (response_type=token): HTTP $STATUS"

if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
  echo "[WARNING] Implicit flow accepted — tokens appear in URL fragment and browser history"
else
  echo "[OK] Implicit flow rejected"
fi
```

### Step 7: Document chain to ATO

```bash
echo ""
echo "=== ATO chain assessment ==="
cat <<'EOF'
Finding                          Severity  ATO path
-------------------------------- --------- ----------------------------------
redirect_uri bypass to attacker  Critical  Auth code delivered to attacker
                                           -> exchange for access token -> ATO
Missing PKCE (public client)     High      Auth code interception via redirect
                                           -> exchange before victim does -> ATO
Missing state parameter          High      CSRF: force victim to link attacker
                                           account -> ATO or account linking
State fixation                   High      Attacker pre-sets state, victim auth
                                           -> attacker session becomes authed
Code in Referer to third party   Medium    Third party logs code -> ATO if
                                           code not yet exchanged
Implicit flow enabled            Medium    Token in browser history -> theft
Scope escalation                 Medium    Request broader scopes than needed
EOF
```

## Done when

- All 11 redirect_uri bypass techniques have been tested and results recorded
- PKCE enforcement verified for public clients (mobile/SPA)
- State parameter absence and fixation tested
- Referer leakage path assessed
- Implicit flow acceptance checked
- ATO impact chain documented for any confirmed finding

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| All redirect_uri tests return 400 immediately | Server uses exact-match allowlist — this is correct behavior. Document as mitigated |
| Authorization endpoint requires browser session | Use Burp Suite browser to complete the interactive login step, then replay the captured authorization request |
| No client_id found in page source | Check JavaScript bundle files, network requests in DevTools, or the OIDC discovery document |
| PKCE test always returns 400 | Server enforces PKCE for all clients — check if `code_challenge_method=plain` is accepted (weaker than S256) |

## Notes

- redirect_uri bypass severity depends entirely on whether the attacker can receive and exchange the authorization code before the victim does. Tight race windows reduce exploitability.
- PKCE is mandatory for public clients (RFC 9700 / OAuth 2.1). For confidential clients with client secrets, missing PKCE is lower severity.
- The state parameter prevents CSRF but not authorization code interception. Both must be present.
- Mix-up attacks apply when a client supports multiple OAuth providers — the client may send the code intended for provider A to provider B's token endpoint.
- Reference: RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 9700 (OAuth 2.1 draft), OpenID Connect Core 1.0.
