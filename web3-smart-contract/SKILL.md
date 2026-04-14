---
name: web3-smart-contract
description: Smart contract security audit covering 10 DeFi vulnerability classes with Foundry PoC templates
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Audits Solidity smart contracts and DeFi protocols against 10 high-frequency vulnerability classes: Accounting State Desynchronization, Access Control, Incomplete Code Path, Off-By-One, Oracle Manipulation, ERC4626 Attacks, Reentrancy, Flash Loan Attacks, Signature Replay, and Proxy/Upgrade Issues. Guides an auditor from pre-dive assessment through grep-pattern scanning, manual code review, Foundry proof-of-concept test writing, and severity-rated findings report generation.

## When to use

- When performing a security audit of a Solidity smart contract or DeFi protocol
- When triaging a bug bounty submission involving a smart contract vulnerability
- When reviewing a protocol upgrade or new contract deployment before launch
- When estimating risk exposure of a protocol by TVL and audit history

## Prerequisites

- Foundry installed:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  ```
- ripgrep installed for pattern scanning:
  ```bash
  # Debian/Ubuntu
  apt install ripgrep
  # macOS
  brew install ripgrep
  ```
- (Optional) Slither static analyzer:
  ```bash
  pip install slither-analyzer
  ```
- Read access to the contract source code (Hardhat/Foundry project or Etherscan-verified source)
- Environment variable `SECSKILL_CONTRACT_DIR`: path to the contract source root

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_CONTRACT_DIR` | required | Path to the Solidity source directory |
| `SECSKILL_PROTOCOL_NAME` | optional | Protocol name for report labeling |
| `SECSKILL_TVL_USD` | optional | Approximate TVL in USD for risk context |
| `SECSKILL_OUTPUT_DIR` | optional | Directory to save findings and PoC files (default: `./output`) |
| `SECSKILL_RPC_URL` | optional | RPC URL for forked Foundry tests (e.g. mainnet fork) |

## Workflow

### Step 1: Pre-dive assessment

Before reading code, collect signal that shapes audit priorities.

```bash
export SRC="${SECSKILL_CONTRACT_DIR:?Set SECSKILL_CONTRACT_DIR}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export PROTOCOL="${SECSKILL_PROTOCOL_NAME:-unknown}"
mkdir -p "$OUTDIR"

echo "===== Pre-Dive Assessment: $PROTOCOL ====="
echo "TVL (USD)    : ${SECSKILL_TVL_USD:-unknown}"
echo "Source path  : $SRC"
echo "Contract count:"
find "$SRC" -name "*.sol" | grep -v test | grep -v lib | wc -l
echo "Lines of code:"
find "$SRC" -name "*.sol" | grep -v test | grep -v lib | xargs wc -l | tail -1
echo ""
echo "[*] Check: Does the protocol have a prior audit? (check docs/audits/)"
echo "[*] Check: Is the code verified on Etherscan?"
echo "[*] Check: Is there a proxy/upgrade pattern in use?"
```

Pre-dive signal checklist:
- **High TVL (>$10M)**: Elevate severity of all findings — financial impact is large.
- **No prior audit**: Treat all 10 classes as untested; expect basic findings.
- **Proxy/upgrade in use**: Always run Bug Class 10 checks regardless of other findings.
- **Complex DeFi integrations (AMMs, lending protocols)**: Prioritize Bug Classes 5, 6, 8.

### Steps 2–11: Grep-pattern scans (Bug Classes 1–10)

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the complete grep command blocks for all 10 bug classes (BC1 Accounting State Desynchronization through BC10 Proxy/Upgrade Issues).

Run each grep-pattern scan in order. Save output files to `$OUTDIR`. Manually confirm or dismiss each flagged result before creating a finding entry.

Bug class descriptions:
- **BC1** Accounting State Desynchronization (28% of critical findings) — internal accounting diverges from actual balances
- **BC2** Access Control — missing modifiers on privileged functions; apply the sibling function rule
- **BC3** Incomplete Code Path — early returns that skip fee collection, balance updates, or event emissions
- **BC4** Off-By-One (22% of high findings) — `<` vs `<=` in loop bounds, deadlines, and amount checks
- **BC5** Oracle Manipulation — spot price from `getReserves()` without TWAP; Chainlink staleness check
- **BC6** ERC4626 Attacks — vault inflation via 1-wei donation; rounding direction errors
- **BC7** Reentrancy — CEI violations; cross-function and read-only reentrancy
- **BC8** Flash Loan Attacks — governance manipulation, liquidity attacks, collateral manipulation
- **BC9** Signature Replay — missing nonce or chainId in signed messages
- **BC10** Proxy/Upgrade Issues — storage collision, uninitialized implementations, unsafe delegatecall

### Step 12: Write Foundry PoC test for confirmed findings

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the complete Foundry PoC template (reentrancy drain example) and the `forge test` run command.

For each confirmed CRITICAL or HIGH finding, write a Foundry test at `test/PoC_<BugClass>_<FindingTitle>.t.sol`. Use a mainnet fork (`--fork-url $SECSKILL_RPC_URL`) when the protocol interacts with live DeFi primitives.

### Step 13: Assess severity and generate findings report

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the severity table (CRITICAL/HIGH/MEDIUM/LOW/INFO) and the finding detail template.

```markdown
## Smart Contract Audit Findings: <PROTOCOL_NAME>

**TVL**: $<TVL_USD>
**Audit date**: <YYYY-MM-DD>
**Source**: <SECSKILL_CONTRACT_DIR>

### Findings

| ID | Bug Class | Title | Severity | PoC Test |
|----|-----------|-------|----------|----------|
| F-001 | BC7 Reentrancy | Cross-function reentrancy in withdraw() allows ETH drain | CRITICAL | PoC_Reentrancy_WithdrawDrain.t.sol |
| F-002 | BC5 Oracle | Spot price from getReserves() manipulable via flash loan | HIGH | PoC_Oracle_FlashLoan.t.sol |
| F-003 | BC9 Signature | Missing nonce in permit() signature allows replay | MEDIUM | PoC_SignatureReplay.t.sol |
```

## Done when

- All 10 bug class grep scans have been completed and output files saved
- Each flagged finding has been manually confirmed or dismissed
- At least one Foundry PoC test exists for each CRITICAL and HIGH finding, and passes with `forge test`
- Severity has been assigned to every finding
- The findings report includes file references, bug class, impact, and remediation for each finding

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `forge` not found | Foundry not installed | Run `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| PoC test fails to compile | Import paths incorrect | Adjust `remappings.txt` or use `--remappings` flag; check `foundry.toml` |
| Fork test fails with RPC error | Invalid or rate-limited RPC URL | Use a dedicated Alchemy/Infura endpoint; set `SECSKILL_RPC_URL` correctly |
| No grep results for a bug class | Pattern not present in this codebase | Mark that class as N/A with a note; it may still warrant manual review |
| Slither produces excessive false positives | Default detectors too broad | Run with `--detect reentrancy,suicidal,uninitialized-local` to scope to highest-signal detectors |

## Notes

- Bug Class 1 (Accounting State Desynchronization) accounts for ~28% of critical findings in competitive audits — always audit this class thoroughly regardless of code complexity.
- Bug Class 4 (Off-By-One) accounts for ~22% of high severity findings — pay close attention to `<` vs `<=` in every comparison involving amounts, deadlines, and loop bounds.
- A PoC test that passes under `forge test --fork-url <mainnet>` is the gold standard for demonstrating exploitability to a protocol team; it eliminates theoretical ambiguity.
- For ERC4626 vaults (Bug Class 6), always verify rounding direction: deposits round down (favor protocol), withdrawals round up (favor protocol). Any deviation benefits the user at protocol expense, or vice versa, creating an arbitrage or drain vector.
- Foundry reference: https://book.getfoundry.sh/
- OWASP Smart Contract Top 10: https://owasp.org/www-project-smart-contract-top-10/
