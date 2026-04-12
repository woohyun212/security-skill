---
name: encoding-toolkit
description: Encode and decode strings across Base64, URL, Hex, HTML entities, ROT13, and JWT formats
license: MIT
metadata:
  category: crypto
  locale: en
  phase: v1
---

## What this skill does

Automatically detects the encoding format of an input string and performs encode/decode conversions across Base64, URL encoding, Hex, HTML entities, ROT13, and JWT formats. Uses only standard tools: `base64`, `python3`, and `xxd`.

## When to use

- Analyzing encoded strings found in web requests or responses
- Stripping multiple encoding layers in CTF challenges
- Inspecting JWT token headers and payloads
- Converting payloads into various formats for WAF bypass testing

## Prerequisites

- `python3` (uses standard library, no extra installation needed)
- `base64` command (built into Linux/macOS)
- `xxd` command (built into Linux/macOS)

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `INPUT` | Input string to convert | `SGVsbG8gV29ybGQ=` |
| `MODE` | Operation to perform (see list below) | `base64-decode` |

## Workflow

### Step 1: Auto-detect encoding

```bash
INPUT="SGVsbG8gV29ybGQ="

echo "=== Auto-detect encoding ==="
python3 - <<PYEOF
import re, base64, urllib.parse, sys

data = """${INPUT}"""

results = []

# Base64 detection
if re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', data) and len(data) % 4 == 0 and len(data) > 0:
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        results.append(f"[Base64 possible] decoded: {decoded[:80]}")
    except Exception:
        pass

# URL encoding detection
if '%' in data:
    try:
        decoded = urllib.parse.unquote(data)
        results.append(f"[URL encoding possible] decoded: {decoded[:80]}")
    except Exception:
        pass

# Hex detection
if re.fullmatch(r'[0-9a-fA-F]+', data) and len(data) % 2 == 0:
    try:
        decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
        results.append(f"[Hex possible] decoded: {decoded[:80]}")
    except Exception:
        pass

# HTML entity detection
if '&' in data and ';' in data:
    import html
    decoded = html.unescape(data)
    results.append(f"[HTML entity possible] decoded: {decoded[:80]}")

# JWT detection
if data.count('.') == 2 and re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', data):
    results.append("[JWT possible] 3-part dot structure detected -> use Step 4 JWT decode")

if results:
    for r in results:
        print(r)
else:
    print("Auto-detection failed -> specify MODE manually for conversion")
PYEOF
```

### Step 2: Base64 encode/decode

```bash
echo ""
echo "=== Base64 ==="

# Encode
echo -n "$INPUT" | base64
echo "(above: Base64 encoded result)"

# Decode (when input is a Base64 string)
echo "$INPUT" | base64 -d 2>/dev/null && echo "" || echo "(decode failed: not a valid Base64 string)"

# URL-safe Base64 handling (auto padding correction)
python3 -c "
import base64, sys
s = '${INPUT}'
s = s.replace('-', '+').replace('_', '/')
padding = 4 - len(s) % 4
if padding != 4:
    s += '=' * padding
try:
    print('URL-safe Base64 decoded:', base64.b64decode(s).decode('utf-8', errors='replace'))
except Exception as e:
    print('URL-safe Base64 decode failed:', e)
"
```

### Step 3: URL encoding, Hex, HTML, ROT13 conversions

```bash
echo ""
echo "=== Multi-format conversion ==="
python3 - <<PYEOF
import urllib.parse, html, codecs, binascii

data = """${INPUT}"""

print("--- URL Encoding ---")
print("encoded:", urllib.parse.quote(data, safe=''))
print("decoded:", urllib.parse.unquote(data))

print("")
print("--- Hex ---")
hex_enc = data.encode('utf-8').hex()
print("encoded (hex):", hex_enc)
print("0x format    :", ' '.join('0x'+hex_enc[i:i+2] for i in range(0, len(hex_enc), 2)))
try:
    decoded_hex = bytes.fromhex(data).decode('utf-8', errors='replace')
    print("decoded (hex->str):", decoded_hex)
except ValueError:
    print("decoded (hex->str): not a valid Hex string")

print("")
print("--- HTML Entities ---")
print("encoded:", html.escape(data))
print("decoded:", html.unescape(data))

print("")
print("--- ROT13 ---")
print("converted:", codecs.encode(data, 'rot_13'))
PYEOF

echo ""
echo "--- xxd Hex dump ---"
echo -n "$INPUT" | xxd | head -5
```

### Step 4: JWT decode

```bash
echo ""
echo "=== JWT decode ==="
# Set INPUT to the JWT token
JWT_TOKEN="$INPUT"

python3 - <<PYEOF
import base64, json, sys

token = """${JWT_TOKEN}"""
parts = token.split('.')

if len(parts) != 3:
    print("Not a valid JWT format (requires 3 dot-separated parts)")
    sys.exit(0)

def decode_part(part):
    # URL-safe Base64 padding correction
    part = part.replace('-', '+').replace('_', '/')
    padding = 4 - len(part) % 4
    if padding != 4:
        part += '=' * padding
    try:
        decoded = base64.b64decode(part)
        return json.loads(decoded)
    except Exception:
        return decoded.decode('utf-8', errors='replace') if isinstance(decoded, bytes) else str(decoded)

print("=== JWT Header ===")
print(json.dumps(decode_part(parts[0]), indent=2, ensure_ascii=False))

print("")
print("=== JWT Payload ===")
print(json.dumps(decode_part(parts[1]), indent=2, ensure_ascii=False))

print("")
print("=== JWT Signature ===")
print(f"(Base64URL raw): {parts[2]}")
print("Note: signature verification requires the secret key or public key")
PYEOF
```

## Done when

- Possible encoding formats for the input string are automatically detected
- Encode/decode results for Base64, URL, Hex, HTML, and ROT13 are printed
- If input is a JWT, the header, payload, and signature are parsed and printed

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| Base64 decoded result is garbled | Binary data or additional encoding layer present. Check raw bytes with Hex dump |
| JWT payload parse failure | Non-standard JWT (e.g., encrypted JWE). Check `alg`/`enc` fields in the header |
| URL decoded result is still encoded | Double URL encoding. Apply decoding twice |
| ROT13 result is meaningless | A different Caesar cipher, not ROT13. Try all shift values (1-25) |

## Notes

- For multi-layer encoding (e.g., Base64 then URL encoding), apply each step in sequence.
- `cyberchef` (https://gchq.github.io/CyberChef/) is useful for GUI-based multi-step conversion.
- When checking for the JWT `alg: none` attack, always inspect the `alg` value in the header.
