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

### Step 2: Grep-pattern scan — Bug Class 1: Accounting State Desynchronization

Accounting state desynchronization (28% of critical findings) occurs when a contract's internal accounting variables diverge from actual token balances or external state. Common pattern: using `balanceOf(address(this))` instead of a tracked internal variable, or updating state after an external call.

```bash
echo "[*] Bug Class 1: Accounting State Desynchronization"
rg -n "balanceOf\(address\(this\)\)" "$SRC" --include="*.sol" | tee "$OUTDIR/bc1_balance_of_this.txt"
rg -n "\.transfer\(|\.transferFrom\(|\.safeTransfer\(" "$SRC" --include="*.sol" | tee "$OUTDIR/bc1_transfers.txt"
# Flag: state update AFTER external call (CEI violation)
rg -n -A5 "\.call\{" "$SRC" --include="*.sol" | grep -A5 "=" | tee "$OUTDIR/bc1_state_after_call.txt"
echo "[*] Manual check: verify each transfer is reflected in an internal accounting variable"
```

### Step 3: Grep-pattern scan — Bug Class 2: Access Control

Missing or incorrect access control on privileged functions. The sibling function rule: if function A has an access modifier (e.g. `onlyOwner`), every function that performs a similar privileged operation should also be protected.

```bash
echo "[*] Bug Class 2: Access Control"
# Find all external/public functions
rg -n "function .*(external|public)" "$SRC" --include="*.sol" | tee "$OUTDIR/bc2_public_functions.txt"
# Find functions with no modifier
rg -n "function .*(external|public) [^{]*\{" "$SRC" --include="*.sol" | grep -v "override\|view\|pure\|returns" | tee "$OUTDIR/bc2_no_modifier.txt"
# Find privileged modifiers
rg -n "onlyOwner\|onlyAdmin\|onlyRole\|requiresAuth\|Ownable" "$SRC" --include="*.sol" | tee "$OUTDIR/bc2_privileged_functions.txt"
echo "[*] Manual check: apply sibling function rule — every admin-equivalent function must be guarded"
```

### Step 4: Grep-pattern scan — Bug Class 3: Incomplete Code Path

Early returns, missing else branches, or unhandled states that allow code to skip critical logic such as fee collection, balance updates, or event emissions.

```bash
echo "[*] Bug Class 3: Incomplete Code Path"
rg -n "return;" "$SRC" --include="*.sol" | tee "$OUTDIR/bc3_early_returns.txt"
# Flag: if blocks without else where state change occurs
rg -n -B2 -A10 "if \(" "$SRC" --include="*.sol" | grep -B5 "return\b" | tee "$OUTDIR/bc3_conditional_returns.txt"
echo "[*] Manual check: trace each early return path — does it skip balance updates, fee accrual, or event emissions?"
```

### Step 5: Grep-pattern scan — Bug Class 4: Off-By-One

Off-by-one errors (22% of high severity findings) in loop bounds, array indexing, token amount calculations, and timestamp/block comparisons.

```bash
echo "[*] Bug Class 4: Off-By-One"
rg -n "< length\|<= length\|i < .*\.length\|i <= .*\.length" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_loop_bounds.txt"
rg -n "\bblock\.timestamp\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_timestamps.txt"
# Flag: comparisons using < vs <=
rg -n ">=\s*[0-9]\|<=\s*[0-9]\|>\s*[0-9]\|<\s*[0-9]" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_numeric_comparisons.txt"
echo "[*] Manual check: verify < vs <= in loop bounds, deadline checks, and amount validations"
```

### Step 6: Grep-pattern scan — Bug Class 5: Oracle Manipulation

Price oracle attacks where spot prices from AMM pools (e.g. Uniswap `getReserves()`) are used directly without TWAP, allowing flash loan manipulation.

```bash
echo "[*] Bug Class 5: Oracle Manipulation"
rg -n "getReserves\(\)\|token0\(\)\|token1\(\)" "$SRC" --include="*.sol" | tee "$OUTDIR/bc5_spot_price.txt"
rg -n "price\|oracle\|getPrice\|latestAnswer\|latestRoundData" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc5_oracle_calls.txt"
rg -n "consult\|observe\|TWAP\|twap" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc5_twap.txt"
echo "[*] Manual check: if spot price used without TWAP, it is flash-loan manipulable"
echo "[*] Manual check: Chainlink usage — check for stale price (latestRoundData round/updatedAt validation)"
```

### Step 7: Grep-pattern scan — Bug Class 6: ERC4626 Attacks

ERC4626 vault inflation attacks (donate 1 wei to manipulate share price) and rounding direction errors that favor attacker over users.

```bash
echo "[*] Bug Class 6: ERC4626 Attacks"
rg -n "ERC4626\|convertToShares\|convertToAssets\|previewDeposit\|previewMint\|previewWithdraw\|previewRedeem" "$SRC" --include="*.sol" | tee "$OUTDIR/bc6_erc4626.txt"
# Flag rounding: mulDiv without explicit rounding direction
rg -n "mulDiv\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc6_muldiv_rounding.txt"
echo "[*] Manual check: deposits should round DOWN (fewer shares to user), withdrawals should round UP (more assets required)"
echo "[*] Manual check: check for virtual shares/assets offset to mitigate inflation attack"
```

### Step 8: Grep-pattern scan — Bug Class 7: Reentrancy

Cross-function reentrancy, cross-contract reentrancy, and read-only reentrancy where view functions are called mid-execution and return stale state.

```bash
echo "[*] Bug Class 7: Reentrancy"
# Flag: external calls (ETH transfer, low-level call, token transfer) before state update
rg -n "\.call\{value\|\.transfer\(\|\.send\(\|safeTransfer\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc7_external_calls.txt"
# Flag: nonReentrant modifier usage
rg -n "nonReentrant\|ReentrancyGuard" "$SRC" --include="*.sol" | tee "$OUTDIR/bc7_reentrancy_guard.txt"
# Flag: missing nonReentrant on public functions that make external calls
rg -n "function .*(external|public)" "$SRC" --include="*.sol" | grep -v nonReentrant | tee "$OUTDIR/bc7_unguarded_functions.txt"
echo "[*] Manual check: CEI pattern — state changes BEFORE external calls"
echo "[*] Manual check: read-only reentrancy — any view functions called in other protocols that read this contract's state mid-execution?"
```

### Step 9: Grep-pattern scan — Bug Class 8: Flash Loan Attacks

Flash loan vectors beyond oracle manipulation: governance attacks (borrow tokens, vote, repay), liquidity attacks, and collateral manipulation.

```bash
echo "[*] Bug Class 8: Flash Loan Attacks"
rg -n "flashLoan\|flashBorrow\|onFlashLoan\|executeOperation" "$SRC" --include="*.sol" | tee "$OUTDIR/bc8_flashloan.txt"
rg -n "governance\|vote\|proposal\|quorum" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc8_governance.txt"
echo "[*] Manual check: can token balance be flash-borrowed to manipulate governance votes in a single block?"
echo "[*] Manual check: does the protocol use snapshot voting (e.g. OpenZeppelin ERC20Votes) to prevent this?"
```

### Step 10: Grep-pattern scan — Bug Class 9: Signature Replay

Missing nonce or chain ID in signed messages allows replay of valid signatures across transactions or chains.

```bash
echo "[*] Bug Class 9: Signature Replay"
rg -n "ecrecover\|ECDSA\.recover\|SignatureChecker" "$SRC" --include="*.sol" | tee "$OUTDIR/bc9_signatures.txt"
# Flag: nonce and chainId usage
rg -n "nonce\|chainId\|block\.chainid" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc9_nonce_chainid.txt"
# Flag: EIP-712 domain separator
rg -n "DOMAIN_SEPARATOR\|EIP712\|domainSeparator" "$SRC" --include="*.sol" | tee "$OUTDIR/bc9_eip712.txt"
echo "[*] Manual check: every signed message must include nonce + chainId or equivalent replay protection"
```

### Step 11: Grep-pattern scan — Bug Class 10: Proxy/Upgrade Issues

Storage collision between proxy and implementation, uninitialized implementation contracts (can be self-destructed or taken over), and unsafe delegatecall targets.

```bash
echo "[*] Bug Class 10: Proxy/Upgrade Issues"
rg -n "delegatecall\|Proxy\|UUPS\|TransparentUpgradeableProxy\|BeaconProxy" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_proxy.txt"
rg -n "initialize\|initializer\|__.*_init\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_initializers.txt"
rg -n "selfdestruct\|suicide(" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_selfdestruct.txt"
echo "[*] Manual check: implementation contract initializer should be called on deployment (not left uninitialized)"
echo "[*] Manual check: storage layout of proxy and implementation must not collide (use storage gaps)"
```

### Step 12: Write Foundry PoC test for confirmed findings

For each finding confirmed in Steps 2–11, write a Foundry test that reproduces the vulnerability. Use a mainnet fork if the protocol interacts with live DeFi primitives.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Save as: test/PoC_<BugClass>_<FindingTitle>.t.sol
// Run with: forge test --match-path "test/PoC_*" -vvvv [--fork-url $SECSKILL_RPC_URL]

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract PoC_Reentrancy_WithdrawDrain is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Deploy or fork target
        target = new VulnerableContract();
        // Seed with ETH to make the PoC impactful
        vm.deal(address(target), 100 ether);
        vm.deal(attacker, 1 ether);
    }

    function test_PoC_ReentrancyDrain() public {
        vm.startPrank(attacker);

        // Step 1: Deposit initial amount
        target.deposit{value: 1 ether}();

        uint256 balanceBefore = address(attacker).balance;

        // Step 2: Trigger reentrant withdraw
        target.withdraw();

        uint256 balanceAfter = address(attacker).balance;
        uint256 stolen = balanceAfter - balanceBefore;

        emit log_named_uint("ETH stolen", stolen);
        assertGt(stolen, 1 ether, "PoC: drained more than deposited");

        vm.stopPrank();
    }

    // Attacker contract fallback re-enters withdraw
    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw();
        }
    }
}
```

```bash
# Run the PoC
cd "$SECSKILL_CONTRACT_DIR"
forge test --match-path "test/PoC_*" -vvvv \
  ${SECSKILL_RPC_URL:+--fork-url "$SECSKILL_RPC_URL"} \
  | tee "$OUTDIR/poc_results.txt"
```

### Step 13: Assess severity and generate findings report

```markdown
## Smart Contract Audit Findings: <PROTOCOL_NAME>

**TVL**: $<TVL_USD>
**Audit date**: <YYYY-MM-DD>
**Source**: <SECSKILL_CONTRACT_DIR>

### Finding Severity Criteria

| Severity | Criteria |
|----------|----------|
| CRITICAL | Direct loss of funds, unauthorized token minting, or complete protocol takeover |
| HIGH | Significant fund loss under realistic conditions, governance manipulation |
| MEDIUM | Partial fund loss, griefing, or DoS under specific conditions |
| LOW | Best-practice violations, minor economic inefficiencies |
| INFO | Gas optimizations, code quality observations |

### Findings

| ID | Bug Class | Title | Severity | PoC Test |
|----|-----------|-------|----------|----------|
| F-001 | BC7 Reentrancy | Cross-function reentrancy in withdraw() allows ETH drain | CRITICAL | PoC_Reentrancy_WithdrawDrain.t.sol |
| F-002 | BC5 Oracle | Spot price from getReserves() manipulable via flash loan | HIGH | PoC_Oracle_FlashLoan.t.sol |
| F-003 | BC9 Signature | Missing nonce in permit() signature allows replay | MEDIUM | PoC_SignatureReplay.t.sol |

### Finding Detail Template

**[CRITICAL] F-001: Reentrancy in withdraw()**
- **File**: `src/Vault.sol:142`
- **Bug Class**: BC7 — Reentrancy
- **Description**: `withdraw()` transfers ETH before updating `balances[msg.sender]`, allowing a malicious contract to re-enter and drain the vault.
- **Impact**: Complete loss of all ETH held in the contract.
- **PoC**: `test/PoC_Reentrancy_WithdrawDrain.t.sol` — test passes, confirming exploitability.
- **Remediation**: Apply Checks-Effects-Interactions: update `balances[msg.sender] = 0` before the ETH transfer. Add `nonReentrant` modifier from OpenZeppelin ReentrancyGuard as defense-in-depth.
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
