---
name: hash-identify
description: Identify hash algorithm type from a hash string and optionally verify against a known plaintext
license: MIT
metadata:
  category: crypto
  locale: en
  phase: v1
---

## What this skill does

Takes a hash string as input and uses the `hashid` tool to identify the algorithm type. If the user provides a plaintext value, verifies whether it matches the hash using Python `hashlib`. Also provides a reference table of common hash lengths.

## When to use

- When determining the hash type before running a cracking tool (Hashcat, John the Ripper)
- When analyzing an unknown hash value in a CTF challenge
- When quickly classifying hashes found in a database dump

## Prerequisites

- Python 3 and pip required (for `hashid` installation)
- `hashid`: `pip install hashid`
- `python3 hashlib` is part of the standard library — no separate installation needed

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `HASH_VALUE` | Hash string to identify | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `PLAINTEXT` | (Optional) Plaintext to verify against | `password` |

## Workflow

### Step 1: Check and install hashid

```bash
if ! command -v hashid &>/dev/null; then
  echo "hashid not found. Installing..."
  pip install hashid --quiet
else
  echo "hashid is installed"
fi
```

### Step 2: Identify hash type

```bash
HASH_VALUE="5f4dcc3b5aa765d61d8327deb882cf99"

echo "=== Hash type identification ==="
echo "Input hash: $HASH_VALUE"
echo "Length: ${#HASH_VALUE} characters"
echo ""
hashid "$HASH_VALUE" -m 2>&1
# -m : also output Hashcat mode numbers
```

### Step 3: Common hash length reference table

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the hash length reference table and verification candidate mapping.

### Step 4: (Optional) Verify hash against plaintext

```bash
PLAINTEXT="password"  # Set if you have a plaintext to verify

if [ -n "$PLAINTEXT" ] && [ -n "$HASH_VALUE" ]; then
  echo ""
  echo "=== Hash verification: '$PLAINTEXT' vs '$HASH_VALUE' ==="
  python3 - <<PYEOF
import hashlib

plaintext = b"${PLAINTEXT}"
target    = "${HASH_VALUE}".lower().strip()
length    = len(target)

# Determine algorithm candidates based on length
candidates = {
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224"],
    64:  ["sha256", "sha3_256"],
    96:  ["sha384"],
    128: ["sha512", "sha3_512", "blake2b", "blake2s"],
}

algos = candidates.get(length, [])
if not algos:
    print(f"No algorithm candidates for length {length}")
else:
    matched = False
    for algo in algos:
        try:
            h = hashlib.new(algo, plaintext).hexdigest()
            if h == target:
                print(f"[MATCH] {algo.upper()}: '{plaintext.decode()}' -> {h}")
                matched = True
        except Exception as e:
            print(f"[ERROR] {algo}: {e}")
    if not matched:
        print(f"No matching hash found (candidates: {', '.join(a.upper() for a in algos)})")
        print("Note: slow hashes like bcrypt/Argon2/PBKDF2 are not supported by hashlib -> use hashcat")
PYEOF
fi
```

## Done when

- The input hash length and list of possible algorithms are printed
- (If plaintext provided) Match or mismatch is clearly indicated
- Common algorithm length reference table is printed

## Failure modes

| Symptom | Cause and resolution |
|---------|----------------------|
| `hashid: command not found` | Installation failed. Retry with `pip install hashid --user` or check PATH |
| "No algorithms found" | Non-standard hash or encoding (e.g. Base64) included. Decode first and retry |
| No match in verification | Hash includes a salt, or is a slow hash like bcrypt/Argon2. Use hashcat |
| Hash too short (< 32 chars) | Likely a checksum such as CRC32 or Adler32. Confirm with hashid |

## Notes

- bcrypt hashes start with `$2b$` or `$2a$` and cannot be verified with hashlib. Use the `bcrypt` package instead.
- Hashcat mode numbers: refer to `hashid -m` output. Examples: MD5=0, SHA-1=100, bcrypt=3200.
- Salted hashes (e.g. `sha256:10000:salt:hash`) must be split into their components and processed separately.
