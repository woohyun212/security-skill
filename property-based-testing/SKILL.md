---
name: property-based-testing
description: Property-based fuzzing and testing to find security edge cases in crypto, smart contracts, and parsers across multiple languages
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Guides property-based testing (PBT) across Python, Rust, JavaScript/TypeScript, Solidity, and Go to surface security-relevant edge cases that example-based unit tests systematically miss. Rather than asserting that specific inputs produce specific outputs, PBT defines invariants the system must always satisfy — then lets a framework generate hundreds or thousands of inputs to try to break them. This skill covers property identification, framework selection, test writing, counterexample minimization, and failure triage with a focus on overflow/underflow, deserialization roundtrips, access control invariants, and state machine violations.

## When to use

- When auditing cryptographic primitives, parsers, or serialization libraries for correctness under adversarial input
- When reviewing smart contracts for arithmetic invariants before or alongside a formal audit
- When a function has a large or unbounded input domain that example tests cannot adequately cover
- When debugging a known crash and needing a minimal reproducible input automatically
- When adding regression coverage to a function that previously had a security-relevant bug

## Prerequisites

Install the framework for the target language:

**Python — Hypothesis**
```bash
pip install hypothesis
# Optional: pytest integration
pip install pytest hypothesis
```

**Rust — proptest**
```toml
# Cargo.toml
[dev-dependencies]
proptest = "1"
```

**JavaScript / TypeScript — fast-check**
```bash
npm install --save-dev fast-check
# or
yarn add --dev fast-check
```

**Solidity — Foundry fuzz testing**
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Go — testing/quick (stdlib)**
```go
import "testing/quick"
// No additional installation required
```

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `PBT_TARGET_FILE` | required | Path to the source file or contract under test |
| `PBT_LANGUAGE` | required | Target language: `python`, `rust`, `js`, `solidity`, `go` |
| `PBT_ITERATIONS` | optional | Number of test cases to generate (default: framework default, typically 100) |
| `PBT_OUTPUT_DIR` | optional | Directory to save failing counterexamples (default: `./pbt-output`) |
| `PBT_SEED` | optional | Fixed seed for reproducible runs |

## Workflow

### Step 1: Identify testable properties

Before writing a single test, enumerate the invariants the target must satisfy. Apply the property strength hierarchy from weakest to strongest — stronger properties catch more bugs:

| Tier | Property type | Description | Example |
|------|--------------|-------------|---------|
| 1 | No Exception | Function must not panic/throw for any valid input | Parser never crashes on well-formed input |
| 2 | Type Preservation | Output type/shape matches input type/shape | Encode → decode returns same type |
| 3 | Invariant | A condition always holds regardless of input | Balance after transfer <= balance before |
| 4 | Idempotence | Applying an operation twice yields the same result as once | `normalize(normalize(x)) == normalize(x)` |
| 5 | Roundtrip | `decode(encode(x)) == x` (or the inverse) | Serialization, compression, encoding |

Security-relevant properties to prioritize:
- **Overflow/underflow**: arithmetic result is within safe bounds for all inputs
- **Access control invariant**: restricted function cannot be reached from an unprivileged state
- **State machine consistency**: invalid state transitions are unreachable
- **Deserialization roundtrip**: no data loss or mutation during encode/decode cycles
- **Monotonicity**: fees, interest, or prices only move in the expected direction

### Step 2: Select framework and write properties

**Python (Hypothesis)**

```python
from hypothesis import given, settings
from hypothesis import strategies as st

# Roundtrip property: encode then decode returns original value
@given(st.binary(min_size=1, max_size=1024))
@settings(max_examples=500)
def test_encode_decode_roundtrip(data: bytes) -> None:
    assert decode(encode(data)) == data

# Arithmetic overflow property
@given(st.integers(min_value=0, max_value=2**256 - 1),
       st.integers(min_value=0, max_value=2**256 - 1))
def test_add_no_overflow(a: int, b: int) -> None:
    if a + b < 2**256:
        result = safe_add(a, b)
        assert result == a + b
    else:
        with pytest.raises(OverflowError):
            safe_add(a, b)
```

**Rust (proptest)**

```rust
use proptest::prelude::*;

proptest! {
    // Roundtrip property
    #[test]
    fn encode_decode_roundtrip(data in proptest::collection::vec(0u8..=255, 0..1024)) {
        let encoded = encode(&data);
        let decoded = decode(&encoded).expect("decode should not fail on valid encoded data");
        prop_assert_eq!(data, decoded);
    }

    // Overflow invariant
    #[test]
    fn checked_add_no_panic(a in 0u64..u64::MAX, b in 0u64..u64::MAX) {
        // Must not panic; result must match checked_add
        let result = safe_add(a, b);
        prop_assert_eq!(result, a.checked_add(b));
    }
}
```

**JavaScript / TypeScript (fast-check)**

```typescript
import * as fc from "fast-check";

// Roundtrip property
test("encode/decode roundtrip", () => {
  fc.assert(
    fc.property(fc.uint8Array({ minLength: 1, maxLength: 1024 }), (data) => {
      expect(decode(encode(data))).toEqual(data);
    }),
    { numRuns: 500 }
  );
});

// Access control invariant: unprivileged caller never reaches admin state
test("unprivileged actor cannot reach admin state", () => {
  fc.assert(
    fc.property(
      fc.record({ caller: fc.hexaString({ minLength: 40, maxLength: 40 }),
                  action: fc.constantFrom("transfer", "approve", "stake") }),
      ({ caller, action }) => !applyAction(initialState, caller, action).isAdmin
    )
  );
});
```

**Solidity — Foundry fuzz testing**

```solidity
// test/PropertyTest.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultPropertyTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    // Invariant: total shares never exceed total assets deposited
    function testFuzz_sharesNeverExceedAssets(uint96 amount) public {
        vm.assume(amount > 0);
        deal(address(this), amount);
        vault.deposit{value: amount}();
        assertLe(vault.shares(address(this)), vault.totalAssets());
    }

    // Roundtrip: deposit then withdraw returns same ETH amount
    function testFuzz_depositWithdrawRoundtrip(uint96 amount) public {
        vm.assume(amount > 1 ether / 1000); // ignore dust
        deal(address(this), amount);
        uint256 shares = vault.deposit{value: amount}();
        uint256 returned = vault.withdraw(shares);
        assertEq(returned, amount, "withdraw must return exact deposit");
    }
}
```

Run with:
```bash
# Default 256 runs
forge test --match-contract PropertyTest -v

# Increase iterations for deeper coverage
forge test --match-contract PropertyTest --fuzz-runs 10000 -v
```

**Go (testing/quick)**

```go
func TestEncodeDecodeRoundtrip(t *testing.T) {
    f := func(data []byte) bool {
        encoded := Encode(data)
        decoded, err := Decode(encoded)
        return err == nil && bytes.Equal(data, decoded)
    }
    if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
        t.Error(err)
    }
}
```

### Step 3: Run with sufficient iterations

| Framework | Default runs | Recommended minimum for security review |
|-----------|-------------|----------------------------------------|
| Hypothesis | 100 | 500–10,000 |
| proptest | 256 | 1,000–10,000 |
| fast-check | 100 | 500–5,000 |
| Foundry fuzz | 256 | 1,000–50,000 |
| testing/quick | 100 | 500–5,000 |

Increase iterations for cryptographic or financial logic. For Hypothesis:
```python
@settings(max_examples=10000, deadline=None)
```

For Foundry, set in `foundry.toml`:
```toml
[fuzz]
runs = 10000
seed = "0x1"
```

### Step 4: Analyze failures and minimize counterexamples

When a property fails, all frameworks print a minimal counterexample automatically (shrinking). Record the counterexample, then:

1. Reproduce the failure in isolation with the exact inputs printed.
2. Determine whether the failure is a test logic error or a real bug in the target.
3. Check if the counterexample represents a realistic attack input (e.g., max uint256, empty bytes, zero address).
4. For Hypothesis, use `@reproduce_failure` decorator with the printed database key for CI reproduction.
5. For Foundry, use `--fuzz-seed <seed>` to replay the exact failing sequence.

### Step 5: Fix and verify

After fixing the production code:

1. Re-run the full property suite at the same iteration count to confirm no regression.
2. Add the counterexample as a named example-based test so it is always exercised:
   ```python
   # Hypothesis: pin counterexample as explicit example
   @example(b"\x00\xff")
   @given(st.binary())
   def test_encode_decode_roundtrip(data): ...
   ```
3. Run `./scripts/validate-skills.sh` and `npm test` to confirm the repository is clean.

## Done when

- At least one property per tier (No Exception, Roundtrip, Invariant) has been written and passes for the target
- All properties run at or above the recommended iteration count with zero failures
- Any counterexample found during the session has been triaged: confirmed as bug or dismissed as test logic error
- Confirmed bugs have a fix and a pinned regression test
- No panics, unchecked overflows, or failed assertions remain in the target for the tested input domain

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Framework generates inputs that violate preconditions | Strategy too broad | Add `assume()` / `vm.assume()` / `fc.filter()` to restrict input domain; document the assumption |
| Tests pass at 100 runs but fail at 10,000 | Bug in rare input region | Always run at the higher iteration count for security-sensitive code |
| Shrinking produces a counterexample that looks impossible | Test logic error, not production bug | Re-read the property definition; make sure the assertion matches the intended invariant |
| Foundry fuzz test is slow | Contract does too much in setUp | Move expensive setup to a fixture and reuse state; limit `vm.deal` amounts |
| Hypothesis raises `HealthCheck.too_slow` | Strategy generation is expensive | Use `@settings(suppress_health_check=[HealthCheck.too_slow])` with caution; prefer lighter strategies |
| `proptest` regression file causes CI flakiness | Stale `.proptest-regressions` | Commit the regressions file; it pins known-failing inputs for permanent coverage |

## Notes

- The property strength hierarchy is a useful ordering guide, not a strict rule. Start with the weakest property that exercises the security concern, then add stronger ones as coverage gaps appear.
- Hypothesis maintains a failure database. On CI set `HYPOTHESIS_DATABASE_FILE` to a workspace path to persist discoveries across runs.
- For Solidity, Foundry's invariant testing (`invariant_*` with `targetContract`) is distinct from fuzz testing and better suited for stateful protocol-level invariants. See the Foundry book for details.
- This skill pairs well with `web3-smart-contract` (Foundry fuzz testing for Solidity), `building-secure-contracts` (multi-chain testing), and `testing-handbook-skills` (broader fuzzing methodology).

---

Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
