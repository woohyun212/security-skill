---
name: secure-code-review
description: Security-focused code review with 10-domain checklist and CWE mapping
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

#### Domain 1: Input Validation

- [ ] All user-supplied input is validated for type, length, format, and range before use
- [ ] Validation occurs server-side regardless of client-side validation presence
- [ ] Allowlist validation is used in preference to denylist/blocklist approaches
- [ ] File upload handling validates MIME type server-side (not by file extension alone) and limits file size
- [ ] XML/JSON/YAML parsers are configured to reject external entity references and billion-laugh payloads
- [ ] Path components from user input are normalized and validated against an allowed base path before use (path traversal)

**CWE references**: CWE-20 (Improper Input Validation), CWE-22 (Path Traversal), CWE-434 (Unrestricted File Upload)

---

#### Domain 2: Authentication & Session Management

- [ ] Passwords are hashed with a modern adaptive algorithm: bcrypt, Argon2id, or scrypt (not MD5, SHA-1, or plain SHA-256)
- [ ] Password reset tokens are cryptographically random, single-use, and expire within a short window (≤ 1 hour)
- [ ] Session IDs are regenerated after successful login to prevent session fixation
- [ ] Session tokens have an appropriate idle timeout and absolute expiry
- [ ] `HttpOnly` and `Secure` flags are set on session cookies; `SameSite=Strict` or `Lax` is applied
- [ ] Multi-factor authentication is enforced for privileged accounts and sensitive operations
- [ ] Login, logout, and MFA events are logged with timestamp, user ID, and IP address
- [ ] Account lockout or progressive delay is implemented to defend against brute-force attacks

**CWE references**: CWE-256 (Plaintext Password Storage), CWE-384 (Session Fixation), CWE-307 (Brute Force), CWE-614 (Sensitive Cookie Without Secure Flag)

---

#### Domain 3: Authorization & Access Control

- [ ] Authorization checks are enforced server-side on every request; client-side checks are not relied upon
- [ ] Object-level authorization (IDOR) is verified: the requesting user owns or is permitted to access the specific resource ID
- [ ] Function-level authorization is applied: role or permission checks exist before executing privileged operations
- [ ] Horizontal privilege escalation is prevented: users cannot act on behalf of other users without explicit delegation
- [ ] Vertical privilege escalation is prevented: regular users cannot reach admin or elevated-privilege endpoints
- [ ] Default-deny: access is denied unless explicitly permitted (fail-safe defaults)
- [ ] Forced browsing to sensitive URLs is blocked by server-side authorization, not only hidden links

**CWE references**: CWE-639 (IDOR), CWE-284 (Improper Access Control), CWE-269 (Improper Privilege Management), CWE-276 (Incorrect Default Permissions)

---

#### Domain 4: Injection Prevention

- [ ] All database queries use parameterized statements or a safe ORM; no string concatenation of user input into queries
- [ ] LDAP queries escape or parameterize user input
- [ ] OS command execution does not incorporate user input; if unavoidable, input is strictly allowlisted and shell metacharacters are escaped
- [ ] Template engines are configured to auto-escape output; raw/unescaped rendering of user input is absent
- [ ] HTML output encodes untrusted data contextually (HTML entity encoding for HTML context, JS encoding for script context) to prevent XSS
- [ ] XML/SOAP construction does not concatenate user input directly into XML strings
- [ ] GraphQL queries use variables, not string interpolation, for dynamic values

**CWE references**: CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-90 (LDAP Injection), CWE-94 (Code Injection)

---

#### Domain 5: Cryptography

- [ ] Approved algorithms are used: AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption; RSA-2048+ or ECDSA P-256+ for asymmetric; SHA-256+ for hashing
- [ ] Deprecated algorithms are absent: DES, 3DES, RC4, MD5, SHA-1 are not used for security purposes
- [ ] IVs and nonces are generated with a cryptographically secure random number generator and are not reused
- [ ] Encryption keys are not hardcoded in source code or committed to version control
- [ ] TLS 1.2 or higher is enforced for all data in transit; certificate validation is not disabled (e.g., `verify=False` is absent)
- [ ] Key management follows least privilege: keys are scoped to minimum required permissions and rotated on a defined schedule
- [ ] Randomness used for security (tokens, session IDs, OTPs) comes from `os.urandom`, `crypto.randomBytes`, or equivalent CSPRNG

**CWE references**: CWE-327 (Use of Broken Algorithm), CWE-321 (Hard-coded Cryptographic Key), CWE-330 (Insufficient Randomness), CWE-295 (Improper Certificate Validation)

---

#### Domain 6: Error Handling & Logging

- [ ] Error responses to clients do not expose stack traces, internal file paths, database schema, or version information
- [ ] Generic error messages are returned externally; detailed errors are logged internally only
- [ ] All security-relevant events are logged: authentication attempts, authorization failures, input validation failures, privilege changes
- [ ] Log entries include sufficient context: timestamp (UTC), user/session ID, source IP, event type, and outcome
- [ ] Logs do not contain sensitive data: passwords, tokens, full PAN, or SSNs are not logged
- [ ] Logging failures do not suppress the original error or cause silent failures
- [ ] Logs are written to an append-only or tamper-resistant destination (not a locally writable file without rotation)

**CWE references**: CWE-209 (Error Message Information Exposure), CWE-532 (Sensitive Information in Log), CWE-778 (Insufficient Logging)

---

#### Domain 7: Data Protection

- [ ] Sensitive data is not stored beyond its retention period; deletion or anonymization is implemented
- [ ] PII, PCI data, and credentials are encrypted at rest using approved algorithms
- [ ] Sensitive values are cleared from memory (zeroed) after use where the language permits
- [ ] Sensitive data is not stored in browser localStorage or sessionStorage; secure, HttpOnly cookies are used instead
- [ ] Data minimization: only the fields necessary for a given operation are collected and returned in API responses
- [ ] Backups of sensitive data are encrypted with the same or stronger controls as production data
- [ ] Personal data flows to third-party services are documented and contractually governed

**CWE references**: CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Information), CWE-313 (Cleartext Storage in a File)

---

#### Domain 8: Dependency Security

- [ ] A software bill of materials (SBOM) or lock file is committed and kept up to date
- [ ] No known-vulnerable dependency versions are present (cross-check with `npm audit`, `pip-audit`, `trivy`, or equivalent)
- [ ] Dependencies are pinned to specific versions (not floating ranges like `^`, `~`, or `*`) in production manifests
- [ ] Transitive dependencies are reviewed for license and security impact
- [ ] Unused dependencies are removed to reduce attack surface
- [ ] A process exists to monitor for new CVEs in production dependencies (e.g., Dependabot, Renovate, or Snyk alerts)

**CWE references**: CWE-1395 (Dependency on Vulnerable Third-Party Component), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

---

#### Domain 9: Configuration Security

- [ ] Secrets (API keys, database credentials, signing keys) are loaded from environment variables or a secrets manager, not hardcoded
- [ ] No secrets are present in source code, committed `.env` files, or version control history
- [ ] Debug mode, verbose logging, and development flags are disabled in production configuration
- [ ] Security HTTP headers are present: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- [ ] CORS policy restricts allowed origins to an explicit allowlist; wildcard `*` is not used for credentialed requests
- [ ] Default credentials on third-party services and infrastructure components have been changed
- [ ] Infrastructure-as-code templates (Terraform, CloudFormation) do not expose resources publicly without explicit authorization

**CWE references**: CWE-260 (Password in Configuration File), CWE-15 (External Control of System or Configuration Setting), CWE-942 (Overly Permissive CORS)

---

#### Domain 10: Race Conditions & Concurrency

- [ ] Time-of-check to time-of-use (TOCTOU) vulnerabilities are absent: authorization and state checks are atomic with the operations they guard
- [ ] Shared mutable state accessed from concurrent threads/goroutines/async handlers is protected by appropriate locks or atomic operations
- [ ] Database operations that require atomicity use transactions with appropriate isolation levels
- [ ] Idempotency is enforced for payment and state-change operations to prevent double-execution
- [ ] Token and OTP consumption is implemented with atomic compare-and-delete (not read-then-delete) to prevent replay under concurrent requests

**CWE references**: CWE-362 (Race Condition), CWE-367 (TOCTOU), CWE-820 (Missing Synchronization)

---

### Step 3: Classify Findings by Severity

After completing the checklist, assign a severity to each finding using the following criteria:

| Severity | Criteria | Examples |
|----------|----------|---------|
| CRITICAL | Directly exploitable for RCE, authentication bypass, or full data compromise with no prerequisites | RCE via unsanitized OS command, JWT `alg: none` accepted |
| HIGH | SQL injection, stored XSS, IDOR, privilege escalation, broken crypto | SQLi in login endpoint, hardcoded signing key, IDOR on `/api/user/{id}` |
| MEDIUM | CSRF on state-changing requests, reflected XSS, sensitive data in logs, missing rate limiting | CSRF on password change, stack trace in error response |
| LOW | Missing security headers, verbose error messages without sensitive data, informational misconfigurations | Missing `X-Content-Type-Options`, default error page version disclosure |
| INFO | Observations, best-practice improvements, or defense-in-depth recommendations | Suggest MFA for non-admin users, recommend key rotation policy |

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

**Finding Detail Template**

Produce one block per finding:

```markdown
### [HIGH] F-001: SQL Injection in payment amount parameter

- **File**: `src/payments/handler.py:142`
- **CWE**: CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
- **Description**: The `amount` parameter from the POST body is concatenated directly into a SQL query string without parameterization in the `process_payment()` function.
- **Impact**: An authenticated attacker can exfiltrate the full `transactions` table or modify transaction records.
- **Proof of Concept**:
  ```
  POST /api/v1/payments
  {"amount": "1 UNION SELECT username, password_hash FROM users-- -"}
  ```
- **Remediation**: Replace the raw query with a parameterized statement:
  ```python
  # Before (vulnerable)
  cursor.execute(f"INSERT INTO transactions (amount) VALUES ({amount})")

  # After (safe)
  cursor.execute("INSERT INTO transactions (amount) VALUES (%s)", (amount,))
  ```
- **References**: https://cwe.mitre.org/data/definitions/89.html

---

### [MEDIUM] F-002: Stack trace exposed in error response

- **File**: `src/api/middleware/error_handler.py:38`
- **CWE**: CWE-209 — Generation of Error Message Containing Sensitive Information
- **Description**: Unhandled exceptions return the full Python traceback in the HTTP response body in all environments due to a missing environment check on the debug error handler.
- **Impact**: Internal file paths, library versions, and application logic are disclosed to unauthenticated callers.
- **Proof of Concept**: Send a malformed JSON body to any endpoint to trigger a 500 response containing the traceback.
- **Remediation**: Gate the debug error handler behind an environment variable check (`if settings.DEBUG`) and ensure the production handler returns a generic `{"error": "Internal server error"}` body only.
- **References**: https://cwe.mitre.org/data/definitions/209.html
```

**Positive Observations**

```markdown
## Positive Security Observations

- Parameterized queries are consistently used throughout the ORM layer (all files except the one identified in F-001)
- Password hashing correctly uses Argon2id with appropriate memory and iteration parameters
- CSRF tokens are validated on all state-changing endpoints in the web layer
```

**Recommendations**

```markdown
## Recommendations

1. Integrate a SAST tool (Semgrep with the `p/python` and `p/security-audit` rulesets) into the CI pipeline to catch injection patterns automatically on each PR.
2. Adopt the `secure-by-default` middleware pattern: apply security headers globally at the framework level rather than per-route.
3. Schedule a quarterly run of the `dependency-audit` skill to monitor transitive dependency CVEs.
4. Consider adopting the `threat-model` skill before the next major feature cycle to proactively identify risks at the design stage.
```

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
