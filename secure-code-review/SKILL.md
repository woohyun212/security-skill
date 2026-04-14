---
name: secure-code-review
description: Security code review across input validation, auth, injection, crypto, error handling, dependencies, and concurrency with CWE mapping
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Performs a structured security-focused code review across 10 domains: Input Validation, Authentication & Session Management, Authorization & Access Control, Injection Prevention, Cryptography, Error Handling & Logging, Data Protection, Dependency Security, Configuration Security, and Race Conditions. Maps findings to CWE identifiers and severity levels, and produces a report with remediation guidance and proof-of-concept notes.

## When to use

- During pull request review for security-sensitive code changes (auth, payments, file handling, crypto)
- Before a production release to verify security controls are in place
- When onboarding a legacy codebase with no prior security review history
- When a bug bounty report or vulnerability disclosure references a code-level flaw requiring root cause analysis

## Prerequisites

- No external tools required (checklist-based; use with source code access)
- Read access to the source code under review
- (Optional) Static analysis output from tools such as Semgrep, CodeQL, or Bandit to supplement manual review
- CWE reference: https://cwe.mitre.org

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `REPO_PATH` | Path to the source code under review | `/src/api/` |
| `LANGUAGE` | Primary language(s) of the codebase | `Python`, `TypeScript`, `Go` |
| `REVIEW_SCOPE` | Files, modules, or PR diff to review | `auth/`, `payments/handler.py`, `PR #342` |
| `APP_TYPE` | Application type | `web-api` / `cli` / `library` / `mobile` |
| `DATA_SENSITIVITY` | Highest data classification handled | `PII` / `PCI` / `internal` / `public` |

## Workflow

### Step 1: Define Review Scope

Before starting the checklist, bound the review to avoid scope creep and ensure thoroughness within the defined boundary.

```markdown
## Review Scope

- **Repository / Path**: <REPO_PATH>
- **Language(s)**: <LANGUAGE>
- **Files reviewed**: <list each file or PR diff>
- **Review date**: <YYYY-MM-DD>
- **Reviewer**: <name or agent>
- **Total lines reviewed**: <approximate>
```

Prioritize review order:
1. Authentication and authorization code
2. External input handling (HTTP request parsing, file uploads, deserialization)
3. Database access and query construction
4. Cryptographic operations
5. Configuration loading and secret handling
6. All remaining files in scope

### Step 2: Apply the 10-Domain Security Checklist

Work through each domain systematically. Mark each item as `[x]` (pass), `[ ]` (fail / finding), or `[-]` (not applicable). For each `[ ]` item, create a finding entry in Step 3.

---

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full 10-domain security checklist with CWE references, severity classification table, and finding detail examples.

Work through each domain systematically. Mark each item as `[x]` (pass), `[ ]` (fail / finding), or `[-]` (not applicable). For each `[ ]` item, create a finding entry in Step 3.

### Step 3: Classify Findings by Severity

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the severity classification table (CRITICAL/HIGH/MEDIUM/LOW/INFO with criteria and examples).

### Step 4: Generate Report

Produce the final report using the templates below.

**Summary**

```markdown
## Secure Code Review — Summary

- **System / PR**: <SYSTEM_NAME or PR link>
- **Files reviewed**: <N files, ~X lines>
- **Review date**: <YYYY-MM-DD>
- **Reviewer**: <name or agent>

### Finding Counts

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 4 |
| INFO | 2 |
| **Total** | **11** |
```

> **Reference**: See [REFERENCE.md](REFERENCE.md) for finding detail examples and positive observations/recommendations templates.

## Done when

- All 10 domains have been worked through for the defined review scope
- Every checklist failure (`[ ]`) has a corresponding finding entry with file, line, CWE, impact, PoC, and remediation
- All findings are assigned a severity level (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- The summary table accurately reflects finding counts
- Positive observations and recommendations sections are complete
- The report is saved or delivered to the requesting team

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Review scope too broad to complete in one session | Large codebase or PR | Prioritize Domains 1–5 (highest risk) first; schedule remaining domains as a follow-up |
| CWE mapping unclear | Unfamiliarity with CWE taxonomy | Search https://cwe.mitre.org using the vulnerability keyword; use the closest parent CWE if an exact match is not found |
| Finding severity difficult to calibrate | Unclear exploitability | Default to the higher severity when in doubt; document the uncertainty in the finding |
| Static analysis tool produces excessive false positives | Overly broad ruleset | Tune the ruleset; use manual review to confirm or dismiss each flagged item |
| Source code unavailable (black-box context) | Reviewing compiled or obfuscated output | Switch to the `owasp-check` skill for behavioral testing; note the limitation in the report |

## Notes

- This skill is intended for manual security review. It complements but does not replace automated SAST/DAST tooling.
- For dependency-specific findings, use the `dependency-audit` skill to get detailed CVE data and upgrade paths.
- Findings marked CRITICAL should block merge or deployment until remediated. HIGH findings should be resolved before the next release unless a documented, time-bound exception is approved.
- CWE IDs provide a stable reference that maps to NVD/CVE data, OWASP guidance, and many SAST tool outputs — always include them in findings shared with development teams.
- When reviewing authentication or cryptographic code, consider pairing with a second reviewer; these domains have the highest consequence for subtle mistakes.
