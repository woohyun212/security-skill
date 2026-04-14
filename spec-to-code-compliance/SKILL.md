---
name: spec-to-code-compliance
description: Verify code implementation matches security specifications, detecting deviations that could introduce vulnerabilities
license: MIT
metadata:
  category: compliance
  locale: en
  phase: v1
---

## What this skill does

Verifies that a code implementation faithfully matches its specification or design document. Parses the spec into discrete requirements, maps each requirement to the corresponding code location, and flags deviations — missing controls, incorrect state transitions, wrong error handling, overlooked edge cases — with severity ratings and MITRE ATT&CK technique mappings where applicable. Produces a compliance matrix as the primary output.

Applicable to:

- **Smart contracts**: EIP compliance (ERC-20, ERC-721, ERC-4626)
- **API implementations**: OpenAPI / Swagger spec adherence
- **Protocol implementations**: RFC compliance (TLS, OAuth 2.0, JWT)
- **Security policies**: access control matrices, data handling policies

This skill is distinct from `threat-model`, which identifies risks before implementation. Here the implementation already exists and is evaluated against a written specification.

## When to use

- After implementing a feature whose specification makes explicit security guarantees (e.g., "only owner can withdraw")
- When auditing a smart contract against its EIP or whitepaper
- When reviewing an RFC-defined protocol implementation for compliance gaps
- When a security policy document exists and code must demonstrably enforce it
- During pre-audit preparation to surface compliance gaps before an external reviewer does
- When a spec has been updated and existing code needs re-validation

## Prerequisites

- A written specification document (RFC, design doc, EIP, OpenAPI schema, security policy)
- Access to the codebase under review (source files readable)
- (Optional) `mitre-attack-lookup` skill available for ATT&CK technique mapping

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `SPEC_SOURCE` | Specification document or URL | `docs/eip-4626.md`, `https://www.rfc-editor.org/rfc/rfc7519` |
| `SPEC_TYPE` | Kind of specification | `EIP` / `RFC` / `OpenAPI` / `design-doc` / `policy` |
| `CODEBASE_PATH` | Root path of the implementation | `./contracts/`, `./src/` |
| `LANGUAGE` | Primary implementation language | `Solidity`, `Python`, `Go`, `TypeScript` |
| `REVIEW_SCOPE` | Optional: limit to specific modules or sections | `Auth flow only`, `Section 4.1–4.6 of RFC` |

## Workflow

### Step 1: Parse spec into requirements list

Read the specification and extract each discrete, verifiable requirement. Number them R-001, R-002, … using the format below. Focus on security-relevant requirements: access controls, state transitions, error conditions, data validation, cryptographic constraints, and ordering guarantees.

```markdown
## Requirements

| ID    | Source         | Requirement Text (verbatim or paraphrased) | Security-Relevant |
|-------|----------------|--------------------------------------------|-------------------|
| R-001 | EIP-4626 §4    | totalAssets() MUST return total managed underlying assets | Yes |
| R-002 | EIP-4626 §6    | deposit() MUST revert if shares output is 0 | Yes |
| R-003 | RFC 7519 §7.2  | Implementations MUST reject JWTs with expired `exp` claim | Yes |
| R-004 | design-doc §3  | Only ADMIN role may call pause()             | Yes |
```

For large specs, filter to security-relevant requirements in the first pass. A requirement is security-relevant if a violation could lead to unauthorized access, data loss, fund loss, privilege escalation, or confidentiality/integrity breach.

### Step 2: Map each requirement to code location

For each requirement, locate the implementing code. Record the file and line range.

```markdown
## Requirement-to-Code Mapping

| ID    | Code Location                         | Implementation Summary |
|-------|---------------------------------------|------------------------|
| R-001 | contracts/Vault.sol:88–102            | totalAssets() sums _asset.balanceOf(address(this)) + idle |
| R-002 | contracts/Vault.sol:145–167           | deposit() checks shares != 0 before mint |
| R-003 | src/auth/jwt.py:54–71                 | _verify_claims() checks exp < time.time() |
| R-004 | contracts/Vault.sol:210               | pause() has onlyRole(ADMIN_ROLE) modifier |
```

Mark requirements as `NOT FOUND` if no implementing code is identified — absence is itself a finding.

### Step 3: Verify implementation matches spec

For each mapped requirement, evaluate whether the implementation satisfies the spec. Check:

- **Access controls**: Are role checks applied correctly and consistently?
- **State transitions**: Are preconditions and postconditions enforced?
- **Error handling**: Does the code revert/reject under spec-mandated error conditions?
- **Edge cases**: Zero values, overflow/underflow, empty inputs, boundary conditions.
- **Ordering**: Does the spec mandate a specific operation order (e.g., checks-effects-interactions)?

Document each finding as a deviation:

```markdown
## Deviations

### DEV-001 — Missing zero-address check on recipient (HIGH)

- **Requirement**: R-002 (EIP-4626 §6): deposit() MUST revert if shares output is 0
- **Code**: contracts/Vault.sol:145–167
- **Spec says**: Function MUST revert when calculated shares == 0
- **Code does**: Returns 0 silently without reverting
- **Impact**: Caller receives no shares but loses assets; silent failure masks accounting errors
- **Severity**: HIGH
- **ATT&CK mapping**: See Step 4

### DEV-002 — JWT expiry check uses server-adjusted time inconsistently (MEDIUM)

- **Requirement**: R-003 (RFC 7519 §7.2)
- **Code**: src/auth/jwt.py:54–71
- **Spec says**: Implementations MUST reject expired tokens
- **Code does**: Uses `datetime.utcnow()` in one branch and `time.time()` in another — timezone offset bug possible
- **Impact**: Valid tokens may be rejected; near-expired tokens may be accepted past expiry
- **Severity**: MEDIUM
```

Severity scale:

| Level    | Criteria |
|----------|----------|
| CRITICAL | Spec deviation directly enables exploitation (fund loss, auth bypass, privilege escalation) |
| HIGH     | Silent failure or missing mandatory control that a spec explicitly requires |
| MEDIUM   | Partial implementation; spec requirement met in common case but edge case unhandled |
| LOW      | Informational gap; spec guidance not followed but exploitability unclear |

### Step 4: Map deviations to MITRE ATT&CK techniques

For each CRITICAL or HIGH deviation, use `mitre-attack-lookup` to identify the most applicable ATT&CK technique. This contextualizes the finding for security teams and detection engineers.

```bash
# Example: missing access control check on a privileged function
# Use mitre-attack-lookup to find relevant technique

MITRIZE_DIR="${HOME}/mitrize"
cd "$MITRIZE_DIR"

# Search for access control-related techniques
python3 scripts/query_attack_md.py search "access control"

# Look up a specific technique directly
python3 scripts/query_attack_md.py technique T1078
```

Common deviation-to-technique mappings (starting points — verify with `mitre-attack-lookup`):

| Deviation Type | Example ATT&CK Technique |
|----------------|--------------------------|
| Missing access control check | T1078 (Valid Accounts) |
| Missing authentication on API endpoint | T1190 (Exploit Public-Facing Application) |
| Improper input validation | T1059 (Command and Scripting Interpreter) |
| Insecure deserialization | T1055 (Process Injection) |
| Missing rate limiting per spec | T1498 (Network Denial of Service) |
| Hardcoded credential contrary to spec | T1552.001 (Credentials in Files) |
| Insufficient logging (spec mandates audit trail) | T1562.002 (Disable Windows Event Logging) |

Add ATT&CK mappings to deviation records:

```markdown
### DEV-001 (continued)
- **ATT&CK**: T1078 (Valid Accounts) — attacker could invoke deposit() as any caller
  and drain vault through repeated 0-share deposits that consume assets without minting
```

### Step 5: Produce compliance matrix

Compile all requirements and their status into a final matrix:

```markdown
## Compliance Matrix

| ID    | Requirement (summary)              | Status        | Deviation | Severity | ATT&CK   |
|-------|------------------------------------|---------------|-----------|----------|----------|
| R-001 | totalAssets() returns managed assets | COMPLIANT   | —         | —        | —        |
| R-002 | deposit() reverts on 0 shares      | NON-COMPLIANT | DEV-001   | HIGH     | T1078    |
| R-003 | JWT exp claim enforced             | PARTIAL       | DEV-002   | MEDIUM   | T1190    |
| R-004 | pause() restricted to ADMIN        | COMPLIANT     | —         | —        | —        |

**Summary**: 2 of 4 requirements fully compliant. 1 HIGH, 1 MEDIUM deviation found.
```

Status values: `COMPLIANT` / `NON-COMPLIANT` / `PARTIAL` / `NOT IMPLEMENTED`

## Done when

- All security-relevant spec requirements are extracted and numbered
- Each requirement is mapped to a code location (or flagged `NOT FOUND`)
- Every deviation has a severity rating and implementation evidence (file:line)
- CRITICAL and HIGH deviations have ATT&CK technique mappings via `mitre-attack-lookup`
- A compliance matrix summarizes all requirements with status, deviation reference, and severity
- Overall compliance percentage is stated (e.g., "18 of 24 requirements COMPLIANT")

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Spec too vague to extract requirements | Informal design doc with no precise language | Ask the author to clarify ambiguous requirements before proceeding; document assumptions made |
| Requirement has no corresponding code | Feature not yet implemented or dead code removed | Mark `NOT IMPLEMENTED`; escalate to engineering if spec mandates it |
| Code location ambiguous across multiple files | Requirement implemented in layers (middleware, library, handler) | Map all layers; note which layer is the authoritative enforcement point |
| ATT&CK mapping unclear for a deviation | Novel deviation type not in common mappings | Use `python3 scripts/query_attack_md.py search <keyword>` to find the closest technique; note uncertainty |
| Spec contradicts itself | Version mismatch between sections | Note the contradiction; use the most restrictive interpretation as the baseline |
| Large spec (100+ requirements) | RFC or complex EIP | Triage by security relevance first; defer informational/performance requirements to a second pass |

## Notes

- This skill covers the gap between design-time assurance (`threat-model`) and runtime assurance (`incident-response`). Run it after implementation and before production deployment.
- Compliance matrices are living documents. Re-run after spec amendments, dependency upgrades, or refactors that touch mapped code locations.
- For smart contract audits, prioritize EIP-defined MUST/SHOULD/MAY requirements (RFC 2119 language). `MUST` violations are always at least HIGH severity.
- For OpenAPI spec compliance, cross-reference response codes, required fields, and authentication scheme definitions — these are common deviation points.
- This skill pairs well with `threat-model` (pre-implementation risk identification), `mitre-attack-lookup` (mapping deviations to ATT&CK techniques), and `secure-code-review` (code-level security analysis). Use `mitre-attack-lookup` to contextualize spec deviations — e.g., a missing access control check maps to T1078 (Valid Accounts).
- Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
