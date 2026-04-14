---
name: constant-time-analysis
description: Detect timing side-channel vulnerabilities in cryptographic code caused by secret-dependent branching and memory access patterns
license: MIT
metadata:
  category: crypto
  locale: en
  phase: v1
---

## What this skill does

Inspects cryptographic source code for timing side-channel vulnerabilities — flaws that allow an attacker to infer secret values by measuring how long operations take. Targets secret-dependent control flow (branches, early returns), variable-time memory accesses (table lookups indexed by secret bytes), and missing or broken constant-time comparison primitives. Combines grep-based static analysis with optional dynamic instrumentation via ctgrind, timecop, or dudect, and maps confirmed findings to MITRE ATT&CK techniques.

## When to use

- Auditing AES, RSA, ECDSA, HMAC, or password-comparison routines for timing leaks
- Reviewing a custom crypto library or a vendor patch that touches sensitive comparison logic
- Verifying that a `memcmp` replacement is truly constant-time before production use
- Checking that compiler flags (`-O2`, LTO, PGO) have not optimized away carefully written constant-time code
- Satisfying a security requirement that mandates constant-time operations for key material handling

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| `grep` / `ripgrep` | Static pattern search | pre-installed / `apt install ripgrep` |
| `objdump` / `gcc` | Disassembly, compilation | `apt install binutils gcc` |
| `valgrind` + ctgrind | Dynamic taint analysis | `apt install valgrind` + build ctgrind from source |
| `timecop` | Compile-time constant-time checker (C) | https://github.com/agl/ctgrind (see also timecop) |
| `dudect` | Statistical timing measurement | https://github.com/oreparaz/dudect |

Only `grep`/`ripgrep` and a compiler are required for the static analysis steps. Dynamic tools are optional but recommended for confirmation.

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_DIR` | Root directory of the crypto source to audit | `./src/crypto` |
| `BINARY` | (optional) Compiled binary or object file for assembly inspection | `./build/libcrypto.so` |
| `COMPILER_FLAGS` | Flags used to build the target | `-O2 -march=native` |

## Workflow

### Step 1: Identify cryptographic functions handling secrets

```bash
TARGET_DIR="./src/crypto"

echo "=== Locating crypto entry points ==="

# Find files likely to contain secret-handling code
rg -l "AES|RSA|ECDSA|HMAC|hmac|memcmp|strcmp|bcrypt|pbkdf|scrypt|password" "$TARGET_DIR" \
  --type c --type cpp --type h

# List functions that accept key/secret/password parameters
rg -n "(\bkey\b|\bsecret\b|\bpassword\b|\bpriv\b|\bseed\b)" "$TARGET_DIR" \
  --type c --type cpp -l
```

### Step 2: Static analysis — secret-dependent branching

```bash
echo "=== Checking for secret-dependent branches ==="

# Early-exit comparisons (common in HMAC/password verification)
rg -n "if\s*\(.*\bmemcmp\b|if\s*\(.*\bstrcmp\b|if\s*\(.*\bstrncmp\b" \
  "$TARGET_DIR" --type c --type cpp

# Loop breaks conditioned on secret bytes
rg -n "break|return|goto" "$TARGET_DIR" --type c --type cpp \
  | rg "for|while" -A2 | head -60

# Direct secret-indexed conditionals
rg -n "if\s*\(\s*\w*(key|secret|priv|byte|buf)\w*\[" \
  "$TARGET_DIR" --type c --type cpp
```

### Step 3: Check for constant-time comparison primitives

```bash
echo "=== Auditing comparison functions ==="

# Dangerous: raw memcmp/strcmp on secrets (compiler may short-circuit)
rg -n "\bmemcmp\b|\bstrcmp\b|\bstrncmp\b|\bstrncasecmp\b" \
  "$TARGET_DIR" --type c --type cpp

# Preferred: constant-time replacements
rg -n "CRYPTO_memcmp\|crypto_memcmp\|timingsafe_memcmp\|timingsafe_bcmp\|ct_memcmp\|secure_compare" \
  "$TARGET_DIR" --type c --type cpp

echo ""
echo "=== Checking OpenSSL / libsodium constant-time API usage ==="
rg -n "CRYPTO_memcmp\|sodium_memcmp\|crypto_verify" "$TARGET_DIR" --type c --type cpp
```

### Step 4: Detect variable-time memory access patterns

```bash
echo "=== Checking for secret-indexed table lookups ==="

# Classic AES S-box or similar: array indexed directly by secret byte
rg -n "\[\s*\w*(key|secret|byte|plaintext|c|b)\w*\s*\]" \
  "$TARGET_DIR" --type c --type cpp \
  | rg "sbox|table|lookup|T0|T1|T2|T3|td|te" -i

# Pointer arithmetic on secret values
rg -n "\*\s*\(\w*(key|secret|priv)\w*\s*\+\s*" "$TARGET_DIR" --type c --type cpp
```

### Step 5: Check compiler flags that can break constant-time code

```bash
COMPILER_FLAGS="-O2 -march=native"  # replace with actual flags

echo "=== Compiler flag analysis ==="

# Flags that may reintroduce branches through auto-vectorization or loop unrolling
echo "Checking for potentially dangerous optimizations:"
echo "$COMPILER_FLAGS" | grep -E "\-O[23s]|\-march=native|\-funroll|\-fprofile|\-flto" \
  && echo "[WARN] High optimization or LTO enabled — verify constant-time properties hold at assembly level" \
  || echo "[OK]   No aggressive optimization flags detected"

# Check for explicit constant-time guards in build system
rg -rn "volatile|__asm__\|barrier\|memory_barrier\|OPENSSL_cleanse" \
  "$TARGET_DIR" --type c --type cpp | head -30
```

### Step 6: Inspect assembly output for secret-dependent jumps

```bash
BINARY="./build/libcrypto.so"   # or a .o file
FUNCTION="aes_encrypt"           # function to inspect

echo "=== Disassembling $FUNCTION ==="
objdump -d "$BINARY" | awk "/^[0-9a-f]+ <${FUNCTION}>/{found=1} found{print; if(/^$/)exit}" \
  | grep -E "j[a-z]+\s|cmov" | head -40

echo ""
echo "Looking for conditional jumps (je, jne, jl, jg, js, jb, ja...):"
objdump -d "$BINARY" | awk "/^[0-9a-f]+ <${FUNCTION}>/{found=1} found{print; if(/^$/)exit}" \
  | grep -cE "^\s+[0-9a-f]+:\s+[0-9a-f ]+\s+j[^m]"
echo "conditional jumps found in $FUNCTION (0 is ideal for constant-time code)"
```

### Step 7: Dynamic analysis with ctgrind (valgrind plugin)

```bash
# ctgrind marks secret memory as "undefined" from Valgrind's perspective.
# Any branch or memory address derived from secret data triggers a report.

# Build ctgrind from source (one-time)
# git clone https://github.com/agl/ctgrind && cd ctgrind && make

echo "=== Running ctgrind dynamic taint analysis ==="
# Wrap the test binary that exercises the crypto function with secrets:
valgrind --tool=memcheck \
         --undef-value-errors=yes \
         --track-origins=yes \
         ./test_crypto_binary 2>&1 | grep -E "Conditional jump|Invalid read|Use of uninitialised" | head -40

echo ""
echo "A 'Conditional jump or move depends on uninitialised value(s)' message"
echo "pointing into your crypto function indicates a timing side channel."
```

### Step 8: Statistical timing measurement with dudect

```bash
# dudect performs Welch's t-test on two input classes (random vs fixed secret).
# A |t| > 4.5 is a strong indicator of timing leakage.

echo "=== Running dudect statistical timing test ==="
# Assumes dudect harness is compiled with your target function:
./dudect_test | tail -20

echo ""
echo "Interpret results:"
echo "  |t| < 4.5  -> no significant timing difference detected"
echo "  |t| >= 4.5 -> timing leakage likely present"
echo "  |t| >= 10  -> strong evidence of timing side channel"
```

### Step 9: Report findings with MITRE ATT&CK mapping

```bash
echo "=== Timing Side-Channel Findings Summary ==="
echo ""
echo "ATT&CK Technique Mapping:"
echo "  T1040  Network Sniffing        — attacker captures ciphertext/timing data on the wire"
echo "  T1557  Adversary-in-the-Middle — attacker in network path issues crafted inputs and"
echo "                                   measures response latency to extract key material"
echo ""
echo "Recommended remediations:"
echo "  1. Replace memcmp/strcmp on secrets with CRYPTO_memcmp (OpenSSL) or"
echo "     timingsafe_memcmp (BSD libc) or sodium_memcmp (libsodium)"
echo "  2. Remove early-return / break patterns in comparison loops"
echo "  3. Replace lookup-table AES with bitsliced or hardware AES-NI implementation"
echo "  4. Annotate secret memory with ct_poison() / ct_unpoison() from timecop to"
echo "     enforce constant-time properties at compile time"
echo "  5. Re-verify constant-time properties after any compiler flag change"
```

## Done when

- All `memcmp`/`strcmp` calls on secret data are identified and assessed
- Secret-dependent branches and early returns are catalogued
- Secret-indexed memory accesses (table lookups) are flagged
- Compiler flags are reviewed for optimizations that break constant-time code
- Assembly output (if binary available) shows no unexplained conditional jumps in crypto hot paths
- Dynamic analysis (ctgrind or dudect) shows no timing leakage, or findings are documented
- A findings summary with ATT&CK technique IDs (T1040, T1557) is produced

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| grep finds no crypto files | Wrong `TARGET_DIR` or non-C/C++ codebase | Adjust `--type` flags; add `--type rust`, `--type go`, etc. |
| `objdump` output empty | Binary stripped or wrong path | Use `objdump -d --no-show-raw-insn` on unstripped binary; rebuild with `-g` |
| ctgrind shows no errors but dudect shows leakage | Compiler optimized out the branch at -O0 but reintroduced it at -O2 | Build test harness with the same flags as production |
| `timingsafe_memcmp` not available | Platform lacks BSD libc extensions | Use `CRYPTO_memcmp` from OpenSSL or copy a reviewed implementation |
| dudect t-value fluctuates across runs | Insufficient samples or OS noise | Increase sample count (`DUDECT_NSAMPLES`), pin CPU frequency, disable turbo boost |
| Assembly shows `cmov` instead of `jcc` | Compiler chose conditional move (branchless) | `cmov` is generally constant-time; verify no memory-access variation remains |

## Notes

- This skill pairs well with `mitre-attack-lookup` (mapping timing attacks to ATT&CK techniques like T1040 and T1557), `hash-identify` (checking hash algorithm strength), and `secure-code-review` (broader code security review).
- The canonical constant-time comparison for OpenSSL is `CRYPTO_memcmp`; for libsodium use `sodium_memcmp`; for Go use `subtle.ConstantTimeCompare`.
- AES table-lookup implementations (common in pure-software AES before AES-NI) are inherently vulnerable to cache-timing attacks (Bernstein's cache-timing attack, 2005). Prefer AES-NI intrinsics or bitsliced implementations.
- Compiler optimizations can silently remove hand-written constant-time code. Always verify at the assembly level after a compiler or flag change.
- For Rust, use the `subtle` crate (`ConstantTimeEq`, `ConstantTimeLess`) to enforce constant-time properties through the type system.
- Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
