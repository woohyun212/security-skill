# Reference: secure-code-review

## 10-Domain Security Checklist with CWE Mapping

### Domain 1: Input Validation

- [ ] All user-supplied input is validated for type, length, format, and range before use
- [ ] Validation occurs server-side regardless of client-side validation presence
- [ ] Allowlist validation is used in preference to denylist/blocklist approaches
- [ ] File upload handling validates MIME type server-side (not by file extension alone) and limits file size
- [ ] XML/JSON/YAML parsers are configured to reject external entity references and billion-laugh payloads
- [ ] Path components from user input are normalized and validated against an allowed base path before use (path traversal)

**CWE references**: CWE-20 (Improper Input Validation), CWE-22 (Path Traversal), CWE-434 (Unrestricted File Upload)

---

### Domain 2: Authentication & Session Management

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

### Domain 3: Authorization & Access Control

- [ ] Authorization checks are enforced server-side on every request; client-side checks are not relied upon
- [ ] Object-level authorization (IDOR) is verified: the requesting user owns or is permitted to access the specific resource ID
- [ ] Function-level authorization is applied: role or permission checks exist before executing privileged operations
- [ ] Horizontal privilege escalation is prevented: users cannot act on behalf of other users without explicit delegation
- [ ] Vertical privilege escalation is prevented: regular users cannot reach admin or elevated-privilege endpoints
- [ ] Default-deny: access is denied unless explicitly permitted (fail-safe defaults)
- [ ] Forced browsing to sensitive URLs is blocked by server-side authorization, not only hidden links

**CWE references**: CWE-639 (IDOR), CWE-284 (Improper Access Control), CWE-269 (Improper Privilege Management), CWE-276 (Incorrect Default Permissions)

---

### Domain 4: Injection Prevention

- [ ] All database queries use parameterized statements or a safe ORM; no string concatenation of user input into queries
- [ ] LDAP queries escape or parameterize user input
- [ ] OS command execution does not incorporate user input; if unavoidable, input is strictly allowlisted and shell metacharacters are escaped
- [ ] Template engines are configured to auto-escape output; raw/unescaped rendering of user input is absent
- [ ] HTML output encodes untrusted data contextually (HTML entity encoding for HTML context, JS encoding for script context) to prevent XSS
- [ ] XML/SOAP construction does not concatenate user input directly into XML strings
- [ ] GraphQL queries use variables, not string interpolation, for dynamic values

**CWE references**: CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-90 (LDAP Injection), CWE-94 (Code Injection)

---

### Domain 5: Cryptography

- [ ] Approved algorithms are used: AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption; RSA-2048+ or ECDSA P-256+ for asymmetric; SHA-256+ for hashing
- [ ] Deprecated algorithms are absent: DES, 3DES, RC4, MD5, SHA-1 are not used for security purposes
- [ ] IVs and nonces are generated with a cryptographically secure random number generator and are not reused
- [ ] Encryption keys are not hardcoded in source code or committed to version control
- [ ] TLS 1.2 or higher is enforced for all data in transit; certificate validation is not disabled (e.g., `verify=False` is absent)
- [ ] Key management follows least privilege: keys are scoped to minimum required permissions and rotated on a defined schedule
- [ ] Randomness used for security (tokens, session IDs, OTPs) comes from `os.urandom`, `crypto.randomBytes`, or equivalent CSPRNG

**CWE references**: CWE-327 (Use of Broken Algorithm), CWE-321 (Hard-coded Cryptographic Key), CWE-330 (Insufficient Randomness), CWE-295 (Improper Certificate Validation)

---

### Domain 6: Error Handling & Logging

- [ ] Error responses to clients do not expose stack traces, internal file paths, database schema, or version information
- [ ] Generic error messages are returned externally; detailed errors are logged internally only
- [ ] All security-relevant events are logged: authentication attempts, authorization failures, input validation failures, privilege changes
- [ ] Log entries include sufficient context: timestamp (UTC), user/session ID, source IP, event type, and outcome
- [ ] Logs do not contain sensitive data: passwords, tokens, full PAN, or SSNs are not logged
- [ ] Logging failures do not suppress the original error or cause silent failures
- [ ] Logs are written to an append-only or tamper-resistant destination (not a locally writable file without rotation)

**CWE references**: CWE-209 (Error Message Information Exposure), CWE-532 (Sensitive Information in Log), CWE-778 (Insufficient Logging)

---

### Domain 7: Data Protection

- [ ] Sensitive data is not stored beyond its retention period; deletion or anonymization is implemented
- [ ] PII, PCI data, and credentials are encrypted at rest using approved algorithms
- [ ] Sensitive values are cleared from memory (zeroed) after use where the language permits
- [ ] Sensitive data is not stored in browser localStorage or sessionStorage; secure, HttpOnly cookies are used instead
- [ ] Data minimization: only the fields necessary for a given operation are collected and returned in API responses
- [ ] Backups of sensitive data are encrypted with the same or stronger controls as production data
- [ ] Personal data flows to third-party services are documented and contractually governed

**CWE references**: CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Information), CWE-313 (Cleartext Storage in a File)

---

### Domain 8: Dependency Security

- [ ] A software bill of materials (SBOM) or lock file is committed and kept up to date
- [ ] No known-vulnerable dependency versions are present (cross-check with `npm audit`, `pip-audit`, `trivy`, or equivalent)
- [ ] Dependencies are pinned to specific versions (not floating ranges like `^`, `~`, or `*`) in production manifests
- [ ] Transitive dependencies are reviewed for license and security impact
- [ ] Unused dependencies are removed to reduce attack surface
- [ ] A process exists to monitor for new CVEs in production dependencies (e.g., Dependabot, Renovate, or Snyk alerts)

**CWE references**: CWE-1395 (Dependency on Vulnerable Third-Party Component), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

---

### Domain 9: Configuration Security

- [ ] Secrets (API keys, database credentials, signing keys) are loaded from environment variables or a secrets manager, not hardcoded
- [ ] No secrets are present in source code, committed `.env` files, or version control history
- [ ] Debug mode, verbose logging, and development flags are disabled in production configuration
- [ ] Security HTTP headers are present: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- [ ] CORS policy restricts allowed origins to an explicit allowlist; wildcard `*` is not used for credentialed requests
- [ ] Default credentials on third-party services and infrastructure components have been changed
- [ ] Infrastructure-as-code templates (Terraform, CloudFormation) do not expose resources publicly without explicit authorization

**CWE references**: CWE-260 (Password in Configuration File), CWE-15 (External Control of System or Configuration Setting), CWE-942 (Overly Permissive CORS)

---

### Domain 10: Race Conditions & Concurrency

- [ ] Time-of-check to time-of-use (TOCTOU) vulnerabilities are absent: authorization and state checks are atomic with the operations they guard
- [ ] Shared mutable state accessed from concurrent threads/goroutines/async handlers is protected by appropriate locks or atomic operations
- [ ] Database operations that require atomicity use transactions with appropriate isolation levels
- [ ] Idempotency is enforced for payment and state-change operations to prevent double-execution
- [ ] Token and OTP consumption is implemented with atomic compare-and-delete (not read-then-delete) to prevent replay under concurrent requests

**CWE references**: CWE-362 (Race Condition), CWE-367 (TOCTOU), CWE-820 (Missing Synchronization)

---

## Severity Classification Table

| Severity | Criteria | Examples |
|----------|----------|---------|
| CRITICAL | Directly exploitable for RCE, authentication bypass, or full data compromise with no prerequisites | RCE via unsanitized OS command, JWT `alg: none` accepted |
| HIGH | SQL injection, stored XSS, IDOR, privilege escalation, broken crypto | SQLi in login endpoint, hardcoded signing key, IDOR on `/api/user/{id}` |
| MEDIUM | CSRF on state-changing requests, reflected XSS, sensitive data in logs, missing rate limiting | CSRF on password change, stack trace in error response |
| LOW | Missing security headers, verbose error messages without sensitive data, informational misconfigurations | Missing `X-Content-Type-Options`, default error page version disclosure |
| INFO | Observations, best-practice improvements, or defense-in-depth recommendations | Suggest MFA for non-admin users, recommend key rotation policy |

---

## Finding Detail Examples

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
