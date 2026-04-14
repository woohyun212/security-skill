---
name: building-secure-contracts
description: Multi-chain smart contract security for Solana, Algorand, Cairo, Cosmos, Substrate, and TON with pre-audit readiness checks
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Guides security engineers and auditors through smart contract security reviews on non-EVM chains: Solana (Anchor/native), Algorand (AVM/PyTeal), Cairo (Starknet), Cosmos (CosmWasm), Substrate (ink!/FRAME pallets), and TON (FunC/Tact). Covers platform-specific vulnerability patterns, chain-appropriate static analysis tooling, a common vulnerability checklist per platform, and a pre-audit code maturity assessment to determine whether a codebase is ready for a formal audit.

## When to use

- When auditing or reviewing smart contracts on any non-EVM chain (Solana, Algorand, Cairo, Cosmos, Substrate, TON)
- When assessing whether a multi-chain protocol is audit-ready before scheduling a formal engagement
- When triaging a bug bounty submission from a non-EVM chain
- When onboarding to a new chain and needing a structured security checklist
- When mapping vulnerability classes across chains for a cross-chain bridge or interoperability protocol

## Prerequisites

Chain-specific tooling — install only what matches your target platform:

**Solana**
```bash
# Anchor framework (includes anchor-cli with built-in lint)
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked
# Soteria static analyzer (optional, proprietary)
# https://www.soteria.dev/
```

**Cairo / Starknet**
```bash
# cairo-lint (Scarb plugin)
scarb add --dev cairo_lint
# Or standalone
cargo install cairo-lint
```

**Cosmos / CosmWasm**
```bash
# cargo-audit for dependency CVEs
cargo install cargo-audit
# cosmwasm-check for schema and interface validation
cargo install cosmwasm-check
```

**Substrate / ink!**
```bash
cargo install cargo-contract
cargo install cargo-audit
```

**Algorand**
```bash
pip install pyteal tealer   # Tealer: AVM static analysis
```

**TON**
```bash
npm install -g @tact-lang/compiler  # Tact compiler with type checks
# toncli or blueprint for project scaffolding
```

**All platforms**
```bash
# Generic dependency audit
cargo audit        # Rust chains
pip-audit          # Python chains
npm audit          # JS/TS tooling
```

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_CONTRACT_DIR` | required | Path to the contract source root |
| `SECSKILL_CHAIN` | required | Target chain: `solana`, `algorand`, `cairo`, `cosmos`, `substrate`, `ton` |
| `SECSKILL_PROTOCOL_NAME` | optional | Protocol name for report labeling |
| `SECSKILL_OUTPUT_DIR` | optional | Directory for findings output (default: `./output`) |

## Workflow

### Step 1: Identify chain and platform

```bash
export SRC="${SECSKILL_CONTRACT_DIR:?Set SECSKILL_CONTRACT_DIR}"
export CHAIN="${SECSKILL_CHAIN:?Set SECSKILL_CHAIN (solana|algorand|cairo|cosmos|substrate|ton)}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export PROTOCOL="${SECSKILL_PROTOCOL_NAME:-unknown}"
mkdir -p "$OUTDIR"

echo "===== Pre-Audit Assessment: $PROTOCOL ====="
echo "Chain        : $CHAIN"
echo "Source path  : $SRC"

# Count contract source files by chain
case "$CHAIN" in
  solana|cosmos|substrate)
    find "$SRC" -name "*.rs" | grep -v target | grep -v tests | wc -l
    ;;
  cairo)
    find "$SRC" -name "*.cairo" | wc -l
    ;;
  algorand)
    find "$SRC" -name "*.py" -o -name "*.teal" | wc -l
    ;;
  ton)
    find "$SRC" -name "*.fc" -o -name "*.tact" | wc -l
    ;;
esac

echo "[*] Check: Is there a prior audit report in docs/ or audits/?"
echo "[*] Check: Are test files present and covering happy + sad paths?"
echo "[*] Check: Is the deployment/migration script reviewed separately?"
```

### Step 2: Static analysis with chain-specific tools

Run the appropriate analyzer for your target chain. Save output to `$OUTDIR`.

```bash
cd "$SRC"
case "$CHAIN" in
  solana)
    anchor build 2>&1 | tee "$OUTDIR/anchor-build.log"
    rg --type rust "pub [a-z_]+: Account" --no-heading | grep -v "Signer\|Mut" \
      > "$OUTDIR/signer-candidates.txt"
    rg --type rust "\.owner\s*!?=\|check_program_id\|constraint.*owner" \
      > "$OUTDIR/ownership-checks.txt"
    ;;
  cairo)
    scarb lint 2>&1 | tee "$OUTDIR/cairo-lint.log"
    grep -rn "\bfelt252\b" "$SRC" --include="*.cairo" | grep "[+\-\*]" \
      > "$OUTDIR/felt-arithmetic.txt"
    grep -rn "#\[external\]\|fn.*external" "$SRC" --include="*.cairo" \
      > "$OUTDIR/external-entrypoints.txt"
    ;;
  cosmos)
    cosmwasm-check "$SRC"/artifacts/*.wasm 2>&1 | tee "$OUTDIR/cosmwasm-check.log"
    cargo audit 2>&1 | tee "$OUTDIR/cargo-audit.log"
    rg --type rust "as u64\|as u128\|as i64\|unchecked_" > "$OUTDIR/unsafe-casts.txt"
    ;;
  substrate)
    cargo contract build 2>&1 | tee "$OUTDIR/cargo-contract-build.log"
    cargo test 2>&1 | tee "$OUTDIR/cargo-test.log"
    cargo audit 2>&1 | tee "$OUTDIR/cargo-audit.log"
    rg --type rust "saturating_add\|saturating_sub\|checked_" > "$OUTDIR/arithmetic-patterns.txt"
    ;;
  algorand)
    tealer analyze "$SRC" 2>&1 | tee "$OUTDIR/tealer.log"
    grep -rn "Gtxn\|GroupSize\|group_size" "$SRC" --include="*.py" --include="*.teal" \
      > "$OUTDIR/group-txn-checks.txt"
    grep -rn "AuthAddr\|RekeyTo\|auth_addr" "$SRC" --include="*.py" --include="*.teal" \
      > "$OUTDIR/rekey-checks.txt"
    ;;
  ton)
    find "$SRC" -name "*.tact" | grep -q . && \
      npx tact --check "$SRC" 2>&1 | tee "$OUTDIR/tact-check.log"
    grep -rn "sender()\|msg_sender\|get_sender" "$SRC" \
      --include="*.fc" --include="*.tact" > "$OUTDIR/sender-checks.txt"
    grep -rn "send_raw_message\|BOUNCEABLE\|NON_BOUNCEABLE" "$SRC" \
      --include="*.fc" > "$OUTDIR/bounce-flags.txt"
    ;;
esac
```

### Step 3: Common vulnerability checks per platform

Review findings from Step 2 against these platform-specific vulnerability patterns:

**Solana**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| Missing signer authorization | Account marked `Mut` but not `Signer` — any caller can invoke privileged instructions | CRITICAL |
| Missing ownership check | Program does not verify `account.owner == expected_program_id` | CRITICAL |
| Arbitrary CPI | `invoke()` called with a user-supplied program ID | HIGH |
| Account confusion | Two accounts of the same type not distinguished by a seed or type tag | HIGH |
| Signed integer truncation | `as i64` / `as i32` cast from larger unsigned — wraps silently | MEDIUM |
| Missing freeze authority check | Token mint freeze authority not validated before transfer | MEDIUM |

**Cairo / Starknet**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| felt252 integer overflow | Arithmetic on `felt252` is modular — no overflow panic; large values silently wrap | HIGH |
| Missing caller validation | `get_caller_address()` result never compared to stored owner/admin | CRITICAL |
| Reentrancy via external calls | `call_contract_syscall` before state write — classic CEI violation | HIGH |
| Storage collision | Two storage variables mapped to the same key | MEDIUM |
| Unrestricted upgrade | `upgrade()` entrypoint missing `assert_only_owner()` | CRITICAL |

**Cosmos / CosmWasm**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| Unsafe integer cast | `as u64`/`as u128` truncation from larger type | HIGH |
| Missing admin check | `execute` handler never checks `info.sender == config.admin` | CRITICAL |
| Reentrancy via sub-messages | State mutation after `CosmosMsg::Wasm(WasmMsg::Execute...)` | HIGH |
| Reply handler injection | Untrusted contract address in `ReplyOn::Always` sub-message | HIGH |
| Denom confusion | Native denom not validated; attacker substitutes malicious token | MEDIUM |

**Substrate / ink!**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| Missing origin check | Dispatchable missing `ensure_signed!` or `ensure_root!` | CRITICAL |
| Unbounded storage growth | Vec/Map in storage with no size cap — DoS via storage bloat | HIGH |
| Weight underestimation | Benchmark weight lower than actual computation — block weight abuse | HIGH |
| Unsafe arithmetic | Direct `+`/`-`/`*` on `Balance` instead of `checked_add`/`saturating_add` | MEDIUM |
| ink! re-entrancy | Cross-contract call before storage flush; ink! v4+ has `#[ink(storage)]` ordering rules | HIGH |

**Algorand**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| Missing group transaction validation | Smart contract doesn't verify `GroupSize` or `Gtxn` field constraints | HIGH |
| Unsigned transaction acceptance | Contract accepts `RekeyTo != ZeroAddress` — account can be rekeyed by attacker | CRITICAL |
| Fee siphoning | Application doesn't constrain `Gtxn[i].Fee` — excess fees drain the account | MEDIUM |
| Logic sig replay | Delegated logic sig has no lease or round constraint — replayable | HIGH |
| CloseRemainderTo not checked | Attacker drains account via `CloseRemainderTo` field | CRITICAL |

**TON**

| Vulnerability | Pattern to check | Severity |
|---------------|-----------------|----------|
| Missing sender authorization | Handler processes incoming messages without checking `sender()` | CRITICAL |
| Non-bounceable to uninitialized contract | Sending to a contract that may not exist without `BOUNCEABLE` flag — funds lost | HIGH |
| Gas forwarding attack | Forwarding all gas via `send_raw_message(msg, 64)` — caller drains balance | HIGH |
| Missing state init validation | Deploying a contract with attacker-controlled `StateInit` | HIGH |
| Op-code confusion | Message body op-code not validated — handler falls through to wrong branch | MEDIUM |

### Step 4: Pre-audit code maturity assessment

Answer each question. A "No" on any REQUIRED item blocks audit readiness.

```
Pre-Audit Maturity Checklist: $PROTOCOL ($CHAIN)
================================================

REQUIRED (blocking)
[ ] Source code is complete and matches the deployed/to-be-deployed version
[ ] All external dependencies are pinned (Cargo.lock / package-lock.json committed)
[ ] Test suite exists with at least unit tests covering core logic
[ ] README or docs describe the protocol's intended behavior and trust assumptions
[ ] No TODO / FIXME / HACK comments in security-critical paths

RECOMMENDED (non-blocking, note in report)
[ ] Integration or end-to-end tests cover multi-party interactions
[ ] Threat model document exists (what assets, what attackers)
[ ] Prior audit reports are available (helps scope delta review)
[ ] CI pipeline runs tests and lints on every PR
[ ] Deployment scripts and upgrade procedures are documented
```

```bash
# Quick check for blocking code smell
grep -rn "TODO\|FIXME\|HACK\|XXX\|WORKAROUND" "$SRC" \
  --include="*.rs" --include="*.cairo" --include="*.py" \
  --include="*.fc" --include="*.tact" \
  | grep -v target | grep -v "\.git" \
  > "$OUTDIR/tech-debt.txt"
wc -l "$OUTDIR/tech-debt.txt"
echo "[*] Review tech-debt.txt — items in security-critical paths block audit readiness"
```

### Step 5: Generate findings report

```markdown
## Multi-Chain Contract Security Review: <PROTOCOL_NAME>

**Chain**       : <CHAIN>
**Review date** : <YYYY-MM-DD>
**Source**      : <SECSKILL_CONTRACT_DIR>
**Audit ready** : Yes / No (list blocking items if No)

### Findings

| ID | Platform | Vulnerability Class | Location | Severity | Notes |
|----|----------|---------------------|----------|----------|-------|
| F-001 | Solana | Missing signer authorization | src/lib.rs:142 | CRITICAL | withdraw() accepts any caller |
| F-002 | Solana | Arbitrary CPI | src/cpi.rs:87 | HIGH | Program ID from user input |
| F-003 | Cairo | felt252 overflow | src/math.cairo:55 | HIGH | Unchecked balance accumulation |

### Pre-Audit Maturity: <PASS / CONDITIONAL / NOT READY>
<List any blocking items>

### Recommended next steps
1. Fix all CRITICAL findings before audit engagement
2. Add integration tests for <list gaps>
3. Pair with `web3-smart-contract` skill if EVM components are also in scope
```

## Done when

- Chain and platform identified; correct tooling invoked
- Static analysis output saved to `$OUTDIR` and reviewed
- All platform-specific vulnerability patterns checked and confirmed or dismissed
- Pre-audit maturity checklist completed with blocking items noted
- Findings report generated with location references, severity, and remediation notes

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `anchor: command not found` | Anchor CLI not installed | `cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked` |
| `scarb lint` fails with "plugin not found" | cairo_lint Scarb plugin missing | `scarb add --dev cairo_lint` in project root |
| `cosmwasm-check: no such file` | cosmwasm-check not installed | `cargo install cosmwasm-check` |
| `tealer: command not found` | Tealer not installed | `pip install tealer` |
| `cargo audit` shows no vulnerabilities but build fails | Rust toolchain mismatch | Check `rust-toolchain.toml`; run `rustup update` |
| `tact --check` exits non-zero | Type error in Tact source | Fix compiler errors before security review |
| Static analysis shows 0 results | Wrong file extension filter or wrong `$SRC` path | Verify `SECSKILL_CONTRACT_DIR` points to contract sources, not project root |

## Notes

- Solana's Anchor framework catches many authorization issues at the constraint level (`#[account(constraint = ...)]`) — missing constraints are high-value audit targets because Anchor's macro system makes them easy to overlook.
- Cairo's `felt252` type has no overflow — arithmetic wraps modulo the field prime. Always use `u256` or `checked_` equivalents for balance and amount calculations.
- Algorand's group transaction model means vulnerabilities often span multiple transactions in a group — audit the entire atomic group, not just the application call.
- TON's actor model requires careful attention to message bounce handling; lost funds from non-bounceable messages to uninitialized contracts are a common real-world exploit.
- Cosmos/CosmWasm sub-message reply handlers are a frequent reentrancy vector — treat every `ReplyOn::Always` as a potential external call before state flush.
- Substrate weight benchmarks are security-critical: underestimated weights enable block-stuffing DoS. Always run the benchmark suite (`frame-benchmarking`) before audit.
- This skill pairs well with `web3-smart-contract` (Solidity-specific deep audit) and `mitre-attack-lookup` (mapping contract exploits to ATT&CK techniques).
- Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
