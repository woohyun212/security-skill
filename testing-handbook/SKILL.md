---
name: testing-handbook
description: Security testing methodology using fuzzers (AFL++, libFuzzer), sanitizers (ASan, MSan, UBSan), and static analysis for vulnerability discovery
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Guides structured security testing across three pillars: **Fuzzing** (AFL++, libFuzzer, Honggfuzz), **Sanitizers** (ASan, MSan, UBSan, TSan), and **Static Analysis** (Semgrep, CodeQL, Clang Static Analyzer). Covers harness writing, corpus management, crash triage, sanitizer compilation flags, output interpretation, and mapping discovered vulnerabilities to MITRE ATT&CK techniques. Adapted from the Trail of Bits Testing Handbook methodology.

## When to use

- Before shipping a parser, deserializer, network handler, or any code that processes untrusted input
- When auditing a C/C++ codebase for memory safety issues (buffer overflows, use-after-free, uninitialized reads)
- When a code review or SAST scan flags a high-risk function that needs empirical validation
- When setting up a continuous fuzzing pipeline (CI integration, corpus persistence)
- When triage is needed on a crash or sanitizer report of unknown severity

## Prerequisites

| Tool | Install | Notes |
|------|---------|-------|
| AFL++ | `apt install afl++` or build from source | Recommended fuzzer for binary targets |
| libFuzzer | Bundled with Clang/LLVM (≥ 6.0) | In-process fuzzer; requires harness |
| Honggfuzz | `apt install honggfuzz` or `go install github.com/google/honggfuzz` | Good for network/persistent mode |
| Clang/LLVM | `apt install clang` | Required for sanitizer instrumentation |
| Semgrep | `pip install semgrep` | SAST; free community rules available |
| CodeQL CLI | Download from [github.com/github/codeql-action](https://github.com/github/codeql-action/releases) | SAST; requires CodeQL database build |
| Clang Static Analyzer | Bundled with Clang | Lightweight SAST via `scan-build` |

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `TARGET_FUNCTION` | Function(s) or code path(s) to test | `parse_http_request()`, `deserialize_json()` |
| `TARGET_BINARY` | Compiled target or library under test | `./build/libparser.so`, `./bin/server` |
| `CORPUS_DIR` | Directory of seed inputs for the fuzzer | `./corpus/`, `./tests/fixtures/` |
| `LANGUAGE` | Primary language of the target | `C`, `C++`, `Rust`, `Go` |
| `BUILD_FLAGS` | Sanitizer and instrumentation flags | `-fsanitize=address,undefined -g` |

## Workflow

### Step 1: Select target functions

Prioritize functions that handle untrusted input. High-value targets:

1. Network packet/protocol parsers
2. File format deserializers (JSON, XML, protobuf, custom binary)
3. Compression/decompression routines
4. Authentication token validation
5. Command-line argument parsers (especially in setuid binaries)
6. Any code reachable from a network port without prior authentication

```bash
# Use Semgrep to quickly surface risky patterns before choosing targets
semgrep --config p/c --lang c ./src/ 2>/dev/null | grep -E "(buffer|memcpy|strcpy|sprintf|gets)" | head -40
```

### Step 2: Write a fuzzing harness

**libFuzzer harness template (C/C++)**

```c
// harness.c — compiled with: clang -fsanitize=fuzzer,address -g -o harness harness.c target.c
#include <stdint.h>
#include <stddef.h>

// Include target header
#include "target.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Guard against trivially invalid inputs
    if (size < 4) return 0;

    // Call the function under test with fuzz data
    parse_target(data, size);

    return 0;  // Non-zero return aborts this input (reserved for future use)
}
```

**AFL++ harness template**

```c
// afl_harness.c — compiled with: afl-clang-fast -fsanitize=address -g -o afl_target afl_harness.c target.c
#include <stdio.h>
#include <stdlib.h>
#include "target.h"

int main(int argc, char **argv) {
    // AFL++ persistent mode (recommended — faster than fork mode)
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        parse_target(buf, len);
    }
    return 0;
}
```

### Step 3: Compile with sanitizers

Sanitizers detect memory and undefined behavior errors at runtime. Always enable during fuzzing and testing.

| Sanitizer | Flag | Detects |
|-----------|------|---------|
| AddressSanitizer (ASan) | `-fsanitize=address` | Heap/stack buffer overflows, use-after-free, double-free |
| MemorySanitizer (MSan) | `-fsanitize=memory` | Uninitialized memory reads (requires all deps recompiled) |
| UndefinedBehaviorSanitizer (UBSan) | `-fsanitize=undefined` | Integer overflow, null deref, misaligned access |
| ThreadSanitizer (TSan) | `-fsanitize=thread` | Data races in multithreaded code |

```bash
# Recommended combined flags for fuzzing (ASan + UBSan)
CFLAGS="-fsanitize=address,undefined -fsanitize-recover=all -g -O1 -fno-omit-frame-pointer"
CXXFLAGS="$CFLAGS"

# For libFuzzer: add -fsanitize=fuzzer
clang $CFLAGS -fsanitize=fuzzer -o ./harness harness.c target.c

# For AFL++: use afl-clang-fast wrapper
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast $CFLAGS -o ./afl_target afl_harness.c target.c

# Note: MSan and ASan are mutually exclusive — run in separate builds
# Note: TSan is incompatible with ASan — run separately
```

### Step 4: Run the fuzzer with a corpus

```bash
# --- libFuzzer ---
mkdir -p ./corpus ./crashes
# Seed corpus from existing test inputs (improves coverage significantly)
cp ./tests/fixtures/* ./corpus/

# Run libFuzzer (stops on crash or -max_total_time reached)
./harness -max_total_time=3600 -artifact_prefix=./crashes/ ./corpus/

# Resume a previous run (reuses corpus)
./harness -max_total_time=3600 -artifact_prefix=./crashes/ ./corpus/

# --- AFL++ ---
mkdir -p ./afl_in ./afl_out
cp ./tests/fixtures/* ./afl_in/

# Single-core run
afl-fuzz -i ./afl_in -o ./afl_out -- ./afl_target @@

# Multi-core run (1 primary + N secondary instances)
afl-fuzz -M main -i ./afl_in -o ./afl_out -- ./afl_target @@ &
afl-fuzz -S worker1 -i ./afl_in -o ./afl_out -- ./afl_target @@ &

# Monitor status
afl-whatsup ./afl_out
```

### Step 5: Triage crashes

```bash
# Reproduce a specific crash with the exact input
./harness ./crashes/<crash_file>

# Minimize the crash input (libFuzzer)
./harness -minimize_crash=1 -exact_artifact_path=./crashes/minimized ./crashes/<crash_file>

# Minimize with AFL++
afl-tmin -i ./crashes/<crash_file> -o ./crashes/minimized -- ./afl_target @@

# Deduplicate crashes (AFL++ built-in)
# Unique crashes appear under ./afl_out/main/crashes/

# Get stack trace (ASan output is printed to stderr automatically)
./harness ./crashes/minimized 2>&1 | head -60
```

**Reading ASan output**

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000a30
READ of size 4 at 0x602000000a30 thread T0
    #0 0x401234 in parse_target target.c:87       <-- root cause line
    #1 0x401890 in LLVMFuzzerTestOneInput harness.c:12
SUMMARY: AddressSanitizer: heap-buffer-overflow target.c:87 in parse_target
Shadow bytes around the buggy address: ...
```

Key fields: error type (heap-buffer-overflow, use-after-free, stack-buffer-overflow), root cause file:line, access size and direction (READ/WRITE).

### Step 6: Static analysis

Run SAST tools in parallel with or before fuzzing to find issues that fuzzing may miss (logic bugs, missing authorization checks).

```bash
# --- Semgrep ---
# Run the full C/C++ security ruleset
semgrep --config p/c --config p/default ./src/ --json -o semgrep_results.json

# Run a specific rule
semgrep --config r/c.lang.security.insecure-use-gets ./src/

# Custom rule (YAML file)
semgrep --config ./rules/custom.yaml ./src/

# --- Clang Static Analyzer ---
scan-build -o ./scan_results make
# Open HTML report
xdg-open ./scan_results/*/index.html

# --- CodeQL ---
# 1. Create a CodeQL database
codeql database create ./codeql_db --language=cpp --command="make clean all"

# 2. Run the built-in security queries
codeql database analyze ./codeql_db \
  --format=sarif-latest \
  --output=codeql_results.sarif \
  codeql/cpp-queries:Security/

# 3. View results (SARIF viewer or GitHub Code Scanning)
```

### Step 7: Map findings to MITRE ATT&CK

Use the `mitre-attack-lookup` skill to map discovered vulnerabilities to ATT&CK techniques for threat context and remediation prioritization.

```bash
# Common mappings for findings from fuzzing/sanitizers:
# Heap buffer overflow  -> T1203 (Exploitation for Client Execution)
#                       -> T1190 (Exploit Public-Facing Application)
# Use-after-free        -> T1203, T1203.001
# Integer overflow      -> T1499.004 (Application or System Exploitation)
# Race condition (TSan) -> T1055 (Process Injection) if in shared lib context
# Memory disclosure     -> T1005 (Data from Local System)

# Look up a technique for context
MITRIZE_DIR="${HOME}/mitrize"
[ -d "$MITRIZE_DIR" ] || git clone --depth 1 https://github.com/woohyun212/mitrize.git "$MITRIZE_DIR"
python3 "$MITRIZE_DIR/scripts/query_attack_md.py" technique T1203
python3 "$MITRIZE_DIR/scripts/query_attack_md.py" technique T1190
```

### Step 8: Report findings

For each confirmed vulnerability, document:

```markdown
## Finding: <short title>

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Type**: heap-buffer-overflow / use-after-free / integer-overflow / data-race / ...
- **File / Line**: `src/parser.c:87`
- **Sanitizer**: ASan / MSan / UBSan / TSan
- **ATT&CK**: T1203 — Exploitation for Client Execution
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **Crash input**: `./crashes/minimized` (attach as artifact)
- **Reproduction**: `./harness ./crashes/minimized`
- **Root cause**: <description>
- **Fix**: <recommended remediation>
```

## Done when

- Target functions are identified and harness compiles cleanly with sanitizers enabled
- Fuzzer has run for a meaningful duration (≥ 1 hour for initial coverage; longer for production targets)
- All unique crashes are triaged: minimized, stack trace captured, root cause identified
- Static analysis (at least one tool) has been run and results reviewed
- Each confirmed finding has severity, CWE, ATT&CK technique, and reproduction steps
- Report is complete and delivered to the requesting team or filed as security issue tickets

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Fuzzer shows zero coverage / stuck at low edge count | Harness rejects most inputs too early or target has tight magic-byte checks | Add a dictionary file (`-dict=`); use structure-aware mutation; check that harness does not return early for short inputs |
| Sanitizer build fails | Incompatible sanitizer combination (ASan + MSan) or third-party deps not recompiled | Build separate binaries for ASan and MSan; recompile all dependencies with matching flags |
| Crash does not reproduce | Non-deterministic behavior, ASLR, or race condition | Disable ASLR (`echo 0 > /proc/sys/kernel/randomize_va_space`); use `AFL_NO_FORKSRV=1`; run TSan build for races |
| ASan reports false positive | Sanitizer annotation missing in custom allocator | Add `__attribute__((no_sanitize("address")))` where appropriate or use `ASAN_OPTIONS=strict_string_checks=0` |
| CodeQL database build fails | Build system not invoked correctly or incremental build skips compilation | Run `make clean` before `codeql database create`; ensure all source files compile |
| Semgrep produces excessive false positives | Overly broad community ruleset | Narrow to specific rule IDs; add `# nosemgrep` inline for confirmed false positives with justification |
| Corpus grows too large and slows fuzzer | No corpus minimization | Run `afl-cmin -i ./afl_out/queue -o ./corpus_min ./afl_target @@` periodically |

## Notes

- Fuzzing and sanitizers complement each other: sanitizers turn silent memory bugs into loud crashes that fuzzers can detect. Always compile with sanitizers enabled when fuzzing.
- ASan has approximately 2x runtime overhead and 1.5–3x memory overhead — acceptable for testing but not for production builds.
- Persistent mode in AFL++ (`__AFL_LOOP`) is 10–100x faster than fork mode for targets with expensive initialization.
- For Rust targets, use `cargo fuzz` (libFuzzer-based) and enable `-Z sanitizer=address` via the nightly compiler.
- For Go targets, use `go test -fuzz=FuzzTarget` (built-in since Go 1.18) with `go test -run=FuzzTarget/testdata` for regression.
- Maintain a seed corpus in version control alongside the harness. Good seeds improve coverage faster than any fuzzer configuration tweak.
- This skill pairs well with `mitre-attack-lookup` (mapping discovered vulnerabilities to ATT&CK techniques), `property-based-testing` (higher-level property fuzzing), and `dependency-audit` (checking third-party code before fuzzing your integration).
- Source credit: Adapted from [Trail of Bits Testing Handbook](https://appsec.guide/) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
