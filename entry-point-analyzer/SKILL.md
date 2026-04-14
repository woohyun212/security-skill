---
name: entry-point-analyzer
description: Identify and classify state-changing entry points in smart contracts and applications to map the attack surface
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Systematically discovers and classifies all state-changing entry points in smart contracts (Solidity, Rust/Solana, Move), web APIs, and CLI tools. For each entry point the skill records its type, access control, mutability, and payability — then produces a prioritized attack surface summary that feeds directly into vulnerability testing, threat modeling, and compliance reviews.

Entry point types covered:

- **External/public functions** — callable by any address or user
- **Admin-only functions** — gated by `onlyOwner`, roles, or multisig
- **Payable functions** — accept ETH or native token transfers
- **Callback handlers** — `onERC721Received`, `uniswapV3SwapCallback`, `flashLoan` receivers, etc.
- **Fallback/receive functions** — `fallback()` and `receive()` in Solidity
- **Delegatecall targets** — proxy implementations and libraries called via `delegatecall`
- **Web API endpoints** — REST mutations, GraphQL mutations, WebSocket message handlers
- **CLI sub-commands** — sub-commands that mutate state or invoke privileged operations

## When to use

- Before starting a deep audit: enumerate what can be called and by whom before reading logic
- When scoping a bug bounty engagement: identify unprotected state-changing paths quickly
- When reviewing a protocol upgrade: compare old vs new entry point sets for regressions
- When building a threat model: entry points are the canonical input for threat modeling exercises
- When triaging a reported vulnerability: confirm which entry point the exploit traverses
- When assessing a web API surface: map all mutation endpoints before testing authorization

## Prerequisites

- Read access to the contract source or API codebase
- For Solidity contracts: ripgrep or grep available:
  ```bash
  # Debian/Ubuntu
  apt install ripgrep
  # macOS
  brew install ripgrep
  ```
- (Optional) Slither for automated function classification in Solidity:
  ```bash
  pip install slither-analyzer
  ```
- (Optional) `solc-select` to match the project's compiler version:
  ```bash
  pip install solc-select
  solc-select install 0.8.26 && solc-select use 0.8.26
  ```
- Environment variable `SECSKILL_TARGET`: path to the source root being analyzed

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | required | Path to the source root (Solidity project, API codebase, CLI tool) |
| `SECSKILL_TARGET_TYPE` | optional | `solidity`, `solana`, `move`, `web-api`, `cli` (auto-detected if omitted) |
| `SECSKILL_OUTPUT_DIR` | optional | Directory to write the attack surface report (default: `./output`) |
| `SECSKILL_PROTOCOL_NAME` | optional | Name label for the generated report |

## Workflow

### Step 1: Parse contract or application structure

```bash
export TARGET="${SECSKILL_TARGET:?Set SECSKILL_TARGET}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export PROTO="${SECSKILL_PROTOCOL_NAME:-unknown}"
mkdir -p "$OUTDIR"

echo "===== Entry Point Analysis: $PROTO ====="

# Auto-detect type: solidity (.sol) > solana (.rs) > move (.move) > web-api
if [ -z "$SECSKILL_TARGET_TYPE" ]; then
  find "$TARGET" -name "*.sol" | grep -q . && TARGET_TYPE="solidity" \
    || { find "$TARGET" -name "*.rs" | grep -q . && TARGET_TYPE="solana" \
    || { find "$TARGET" -name "*.move" | grep -q . && TARGET_TYPE="move" \
    || TARGET_TYPE="web-api"; }; }
else
  TARGET_TYPE="$SECSKILL_TARGET_TYPE"
fi
echo "Target type: $TARGET_TYPE"
```

### Step 2: List all entry points

**Solidity — grep for externally callable functions:**

```bash
# All external and public functions (non-view, non-pure = state-changing candidates)
rg --type solidity -n \
  'function\s+\w+\s*\([^)]*\)\s*(external|public)' \
  "$TARGET" \
  | grep -v '//.*function' \
  | tee "$OUTDIR/all_functions.txt"

# Quick count
echo "Total external/public functions: $(wc -l < "$OUTDIR/all_functions.txt")"
```

**Solidity — Slither automated summary (if installed):**

```bash
cd "$TARGET"
slither . --print human-summary 2>/dev/null | tee "$OUTDIR/slither_summary.txt"
slither . --print function-summary 2>/dev/null | tee "$OUTDIR/slither_functions.txt"
```

**Web API — list mutation endpoints (Node/Express example):**

```bash
# REST: POST, PUT, PATCH, DELETE routes
rg -n '(app|router)\.(post|put|patch|delete)\s*\(' "$TARGET" \
  | tee "$OUTDIR/api_mutations.txt"

# GraphQL mutations
rg -n 'type\s+Mutation' "$TARGET" -A 40 \
  | tee "$OUTDIR/graphql_mutations.txt"

# WebSocket message handlers
rg -n '(on|socket)\.(message|emit|on)\s*\(' "$TARGET" \
  | tee "$OUTDIR/ws_handlers.txt"
```

### Step 3: Classify by type

For each function found in Step 2, apply these classification rules:

| Attribute | How to detect |
|-----------|--------------|
| State-changing | Missing `view` or `pure` keyword (Solidity); mutates DB/state in web apps |
| Admin-only | Has `onlyOwner`, `onlyRole`, `requiresAuth`, `isAdmin` guard or equivalent |
| Payable | Marked `payable` (Solidity); accepts payment body in web API |
| Callback | Name matches `onERC*`, `*Callback`, `*Receiver`, `flashLoan*`, `uniswapV3*` |
| Fallback/receive | Named `fallback` or `receive` in Solidity |
| Delegatecall target | Called via `delegatecall` in proxy; `implementation()` or `_implementation()` pattern |

```bash
# Identify payable functions
rg -n 'function\s+\w+\s*\([^)]*\)\s*(external|public)[^{]*payable' \
  "$TARGET" | tee "$OUTDIR/payable_functions.txt"

# Identify fallback and receive
rg -n '(fallback|receive)\s*\(\s*\)\s*(external|public)' \
  "$TARGET" | tee "$OUTDIR/fallback_receive.txt"

# Identify delegatecall usage
rg -n 'delegatecall\s*\(' "$TARGET" | tee "$OUTDIR/delegatecall.txt"

# Identify callback handlers
rg -n 'function\s+(on[A-Z]|.*[Cc]allback|.*[Rr]eceiver)\s*\(' \
  "$TARGET" | tee "$OUTDIR/callbacks.txt"
```

### Step 4: Identify access controls per entry point

```bash
# Functions with explicit access modifiers
rg -n '(onlyOwner|onlyRole|requiresAuth|isAdmin|hasRole|onlyGovernance|onlyMinter)' \
  "$TARGET" | tee "$OUTDIR/access_controlled.txt"

# Functions with no modifier (unprotected candidates)
# Cross-reference all_functions.txt with access_controlled.txt to find the gap
comm -23 \
  <(awk -F: '{print $2}' "$OUTDIR/all_functions.txt" | sort) \
  <(awk -F: '{print $2}' "$OUTDIR/access_controlled.txt" | sort) \
  > "$OUTDIR/potentially_unprotected.txt"

echo "Potentially unprotected state-changing functions:"
cat "$OUTDIR/potentially_unprotected.txt"
```

### Step 5: Map missing controls to vulnerability classes

For each unprotected or weakly protected state-changing entry point, check:

| Missing control | Vulnerability class | ATT&CK mapping |
|-----------------|--------------------|-|
| No auth on state-write function | Unauthorized state modification | T1190 Exploit Public-Facing Application |
| No auth on admin function | Privilege escalation | T1078 Valid Accounts (abused default) |
| Unprotected `selfdestruct` or `delegatecall` | Contract takeover | T1190 |
| Payable function with no reentrancy guard | Reentrancy drain | T1190 |
| Callback with no caller validation | Malicious callback injection | T1190 |
| Unprotected upgrade function | Proxy logic replacement | T1195 Supply Chain Compromise |
| Web API mutation without CSRF/auth token | CSRF / unauthorized mutation | T1190 |

```bash
# Detect unguarded selfdestruct
rg -n 'selfdestruct\s*\(' "$TARGET" | tee "$OUTDIR/selfdestruct.txt"

# Detect upgrade functions (proxy patterns)
rg -n '(upgradeTo|upgradeToAndCall|_authorizeUpgrade)\s*\(' \
  "$TARGET" | tee "$OUTDIR/upgrade_functions.txt"

# Detect reentrancy guard usage
rg -n '(nonReentrant|ReentrancyGuard|_reentrancyGuard)' \
  "$TARGET" | tee "$OUTDIR/reentrancy_guards.txt"
```

### Step 6: Prioritize by risk

Apply this priority matrix to rank findings:

| Priority | Condition |
|----------|-----------|
| Critical | Unprotected state-changing external function with no access control |
| Critical | Unprotected `selfdestruct`, `delegatecall`, or upgrade function |
| High | Payable external function without reentrancy guard |
| High | Callback handler that does not validate `msg.sender` |
| High | `fallback()` or `receive()` that triggers state changes |
| Medium | Admin function accessible to a role broader than intended |
| Medium | Web API mutation endpoint missing CSRF or auth token check |
| Low | View function that leaks sensitive state (information disclosure) |

```bash
# Summarize priority counts
for f in potentially_unprotected selfdestruct upgrade_functions payable_functions callbacks; do
  echo "$f: $(wc -l < "$OUTDIR/${f}.txt")"
done
```

### Step 7: Generate attack surface summary

Write `$OUTDIR/attack_surface.md` with the following structure:

```markdown
## Attack Surface Summary: <PROTOCOL_NAME>
**Path**: <SECSKILL_TARGET> | **Date**: <YYYY-MM-DD> | **Type**: <TARGET_TYPE>

### Entry Point Inventory
| Function / Endpoint | Type | Access Control | Payable | Risk |
|---------------------|------|---------------|---------|------|
| `withdraw(uint256)` | external | none | no | Critical |
| `upgradeTo(address)` | external | onlyOwner | no | Medium |
| `receive()` | receive | none | yes | High |
| `onFlashLoan(...)` | callback | no sender check | no | High |
| `POST /api/transfer` | REST mutation | Bearer token | no | Medium |

### Recommended Actions
1. Add access control to all unprotected state-changing functions.
2. Apply `nonReentrant` to all payable external functions.
3. Validate `msg.sender` in all callback handlers.
4. Restrict upgrade functions to a multisig or timelocked owner.
5. Review all `delegatecall` sites for storage collision risk.
```

## Done when

- All external and public functions are enumerated in `$OUTDIR/all_functions.txt`
- Each entry point is classified by type, access control, payability, and mutability
- Unprotected state-changing functions are isolated in `$OUTDIR/potentially_unprotected.txt`
- Risk priority is assigned to every entry point
- `$OUTDIR/attack_surface.md` is written and contains the full inventory and recommended actions

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `rg` not found | ripgrep not installed | `apt install ripgrep` or `brew install ripgrep` |
| Slither aborts with compiler error | Solidity version mismatch | Run `solc-select use <version>` matching the project's `pragma solidity` |
| `potentially_unprotected.txt` is empty | All functions have modifiers, or cross-reference failed | Manually diff `all_functions.txt` and `access_controlled.txt`; check modifier inheritance in base contracts |
| False positives in unprotected list | Modifiers defined in a base contract not visible to grep | Use `slither . --print function-summary` which resolves inheritance |
| Web API scan misses routes | Framework uses decorators or auto-generated routes | Add framework-specific patterns (e.g., `@app.route` for Flask, `@Controller` for NestJS) |
| Move/Rust codebase not matched | File extension detection missed | Set `SECSKILL_TARGET_TYPE=solana` or `move` explicitly |

## Notes

- An unprotected state-changing external function with no access control is automatically Critical — no further analysis needed to justify the severity.
- For proxied contracts, always check whether the implementation contract's `initialize()` function is protected. Unprotected initializers allow anyone to take ownership of the implementation.
- For Solana programs, entry points are `#[program]` instruction handlers; for Move modules, they are `public entry fun` functions — apply the same classification rules.
- Callbacks that do not validate `msg.sender` are a frequent root cause of flash loan and cross-protocol exploits; treat all unvalidated callbacks as High by default.
- This skill pairs well with `web3-smart-contract` (deep Solidity audit), `building-secure-contracts` (multi-chain pre-audit), `mitre-attack-lookup` (mapping unprotected entry points to ATT&CK techniques like T1190 Exploit Public-Facing Application), and `threat-model` (entry points feed into threat modeling).
- Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
