# Reference: web3-smart-contract

## Grep-Pattern Scan Steps (Bug Classes 1–10)

### Bug Class 1: Accounting State Desynchronization

```bash
echo "[*] Bug Class 1: Accounting State Desynchronization"
rg -n "balanceOf\(address\(this\)\)" "$SRC" --include="*.sol" | tee "$OUTDIR/bc1_balance_of_this.txt"
rg -n "\.transfer\(|\.transferFrom\(|\.safeTransfer\(" "$SRC" --include="*.sol" | tee "$OUTDIR/bc1_transfers.txt"
# Flag: state update AFTER external call (CEI violation)
rg -n -A5 "\.call\{" "$SRC" --include="*.sol" | grep -A5 "=" | tee "$OUTDIR/bc1_state_after_call.txt"
echo "[*] Manual check: verify each transfer is reflected in an internal accounting variable"
```

### Bug Class 2: Access Control

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

### Bug Class 3: Incomplete Code Path

```bash
echo "[*] Bug Class 3: Incomplete Code Path"
rg -n "return;" "$SRC" --include="*.sol" | tee "$OUTDIR/bc3_early_returns.txt"
# Flag: if blocks without else where state change occurs
rg -n -B2 -A10 "if \(" "$SRC" --include="*.sol" | grep -B5 "return\b" | tee "$OUTDIR/bc3_conditional_returns.txt"
echo "[*] Manual check: trace each early return path — does it skip balance updates, fee accrual, or event emissions?"
```

### Bug Class 4: Off-By-One

```bash
echo "[*] Bug Class 4: Off-By-One"
rg -n "< length\|<= length\|i < .*\.length\|i <= .*\.length" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_loop_bounds.txt"
rg -n "\bblock\.timestamp\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_timestamps.txt"
# Flag: comparisons using < vs <=
rg -n ">=\s*[0-9]\|<=\s*[0-9]\|>\s*[0-9]\|<\s*[0-9]" "$SRC" --include="*.sol" | tee "$OUTDIR/bc4_numeric_comparisons.txt"
echo "[*] Manual check: verify < vs <= in loop bounds, deadline checks, and amount validations"
```

### Bug Class 5: Oracle Manipulation

```bash
echo "[*] Bug Class 5: Oracle Manipulation"
rg -n "getReserves\(\)\|token0\(\)\|token1\(\)" "$SRC" --include="*.sol" | tee "$OUTDIR/bc5_spot_price.txt"
rg -n "price\|oracle\|getPrice\|latestAnswer\|latestRoundData" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc5_oracle_calls.txt"
rg -n "consult\|observe\|TWAP\|twap" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc5_twap.txt"
echo "[*] Manual check: if spot price used without TWAP, it is flash-loan manipulable"
echo "[*] Manual check: Chainlink usage — check for stale price (latestRoundData round/updatedAt validation)"
```

### Bug Class 6: ERC4626 Attacks

```bash
echo "[*] Bug Class 6: ERC4626 Attacks"
rg -n "ERC4626\|convertToShares\|convertToAssets\|previewDeposit\|previewMint\|previewWithdraw\|previewRedeem" "$SRC" --include="*.sol" | tee "$OUTDIR/bc6_erc4626.txt"
# Flag rounding: mulDiv without explicit rounding direction
rg -n "mulDiv\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc6_muldiv_rounding.txt"
echo "[*] Manual check: deposits should round DOWN (fewer shares to user), withdrawals should round UP (more assets required)"
echo "[*] Manual check: check for virtual shares/assets offset to mitigate inflation attack"
```

### Bug Class 7: Reentrancy

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

### Bug Class 8: Flash Loan Attacks

```bash
echo "[*] Bug Class 8: Flash Loan Attacks"
rg -n "flashLoan\|flashBorrow\|onFlashLoan\|executeOperation" "$SRC" --include="*.sol" | tee "$OUTDIR/bc8_flashloan.txt"
rg -n "governance\|vote\|proposal\|quorum" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc8_governance.txt"
echo "[*] Manual check: can token balance be flash-borrowed to manipulate governance votes in a single block?"
echo "[*] Manual check: does the protocol use snapshot voting (e.g. OpenZeppelin ERC20Votes) to prevent this?"
```

### Bug Class 9: Signature Replay

```bash
echo "[*] Bug Class 9: Signature Replay"
rg -n "ecrecover\|ECDSA\.recover\|SignatureChecker" "$SRC" --include="*.sol" | tee "$OUTDIR/bc9_signatures.txt"
# Flag: nonce and chainId usage
rg -n "nonce\|chainId\|block\.chainid" "$SRC" --include="*.sol" -i | tee "$OUTDIR/bc9_nonce_chainid.txt"
# Flag: EIP-712 domain separator
rg -n "DOMAIN_SEPARATOR\|EIP712\|domainSeparator" "$SRC" --include="*.sol" | tee "$OUTDIR/bc9_eip712.txt"
echo "[*] Manual check: every signed message must include nonce + chainId or equivalent replay protection"
```

### Bug Class 10: Proxy/Upgrade Issues

```bash
echo "[*] Bug Class 10: Proxy/Upgrade Issues"
rg -n "delegatecall\|Proxy\|UUPS\|TransparentUpgradeableProxy\|BeaconProxy" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_proxy.txt"
rg -n "initialize\|initializer\|__.*_init\b" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_initializers.txt"
rg -n "selfdestruct\|suicide(" "$SRC" --include="*.sol" | tee "$OUTDIR/bc10_selfdestruct.txt"
echo "[*] Manual check: implementation contract initializer should be called on deployment (not left uninitialized)"
echo "[*] Manual check: storage layout of proxy and implementation must not collide (use storage gaps)"
```

---

## Foundry PoC Template

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

---

## Finding Detail Template

```markdown
**[CRITICAL] F-001: Reentrancy in withdraw()**
- **File**: `src/Vault.sol:142`
- **Bug Class**: BC7 — Reentrancy
- **Description**: `withdraw()` transfers ETH before updating `balances[msg.sender]`, allowing a malicious contract to re-enter and drain the vault.
- **Impact**: Complete loss of all ETH held in the contract.
- **PoC**: `test/PoC_Reentrancy_WithdrawDrain.t.sol` — test passes, confirming exploitability.
- **Remediation**: Apply Checks-Effects-Interactions: update `balances[msg.sender] = 0` before the ETH transfer. Add `nonReentrant` modifier from OpenZeppelin ReentrancyGuard as defense-in-depth.
```

---

## Severity Table

| Severity | Criteria |
|----------|----------|
| CRITICAL | Direct loss of funds, unauthorized token minting, or complete protocol takeover |
| HIGH | Significant fund loss under realistic conditions, governance manipulation |
| MEDIUM | Partial fund loss, griefing, or DoS under specific conditions |
| LOW | Best-practice violations, minor economic inefficiencies |
| INFO | Gas optimizations, code quality observations |
