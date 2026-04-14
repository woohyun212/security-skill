# Reference: owasp-check

## OWASP Top 10 2021 — Category Checklist

### A01: Broken Access Control

| # | Question |
|---|----------|
| 1 | Is vertical/horizontal privilege separation implemented? (e.g. regular users cannot access admin pages) |
| 2 | Is bypass of authorization via direct URL access or parameter tampering blocked? |
| 3 | Does the CORS policy explicitly restrict allowed origins? |
| 4 | Is directory listing disabled? |

Reference: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

### A02: Cryptographic Failures

| # | Question |
|---|----------|
| 1 | Is TLS 1.2 or higher applied to data in transit? |
| 2 | Are passwords stored using one-way hashes such as bcrypt/Argon2/scrypt? |
| 3 | Is sensitive data (card numbers, SSNs, etc.) encrypted at rest? |
| 4 | Are there no hardcoded encryption keys or credentials? |

Reference: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

### A03: Injection

| # | Question |
|---|----------|
| 1 | Are parameterized queries (Prepared Statements) used for all DB queries? |
| 2 | Is server-side input validation implemented for user input? |
| 3 | Is raw query usage minimized when using an ORM? |
| 4 | Is user input excluded from OS command execution? |

Reference: https://owasp.org/Top10/A03_2021-Injection/

---

### A04: Insecure Design

| # | Question |
|---|----------|
| 1 | Is threat modeling performed during the design phase? |
| 2 | Are security requirements defined for business logic? |
| 3 | Is rate limiting implemented for critical functions? |

Reference: https://owasp.org/Top10/A04_2021-Insecure_Design/

---

### A05: Security Misconfiguration

| # | Question |
|---|----------|
| 1 | Are unnecessary features, ports, services, and accounts disabled? |
| 2 | Have default accounts/passwords been changed? |
| 3 | Do error messages avoid exposing stack traces or internal information? |
| 4 | Are security HTTP headers (CSP, HSTS, X-Frame-Options, etc.) configured? |

Reference: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

---

### A06: Vulnerable and Outdated Components

| # | Question |
|---|----------|
| 1 | Are the versions of libraries/frameworks in use regularly reviewed? |
| 2 | Is there a process to promptly patch components with known CVEs? |
| 3 | Is an SCA (Software Composition Analysis) tool integrated into CI/CD? |

Reference: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

---

### A07: Identification and Authentication Failures

| # | Question |
|---|----------|
| 1 | Is account lockout or CAPTCHA implemented to defend against brute-force attacks? |
| 2 | Is multi-factor authentication (MFA) supported (especially for admin accounts)? |
| 3 | Is the session ID regenerated after login? |
| 4 | Are password complexity requirements enforced? |

Reference: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

### A08: Software and Data Integrity Failures

| # | Question |
|---|----------|
| 1 | Does the CI/CD pipeline include integrity verification? |
| 2 | Are integrity hashes (SRI) verified for external CDN/packages? |
| 3 | Are untrusted data sources blocked during deserialization? |

Reference: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

---

### A09: Security Logging and Monitoring Failures

| # | Question |
|---|----------|
| 1 | Are login failures, authorization errors, and input validation failures logged? |
| 2 | Do logs avoid including sensitive information (passwords, tokens)? |
| 3 | Is there an alerting/monitoring system for security events? |
| 4 | Are logs stored in a tamper-resistant remote repository? |

Reference: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/

---

### A10: Server-Side Request Forgery (SSRF)

| # | Question |
|---|----------|
| 1 | Is an allowlist used for server-side requests to user-supplied URLs? |
| 2 | Are requests to internal network addresses (169.254.x.x, 10.x.x.x, etc.) blocked? |
| 3 | Is URL redirect following disabled? |

Reference: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

---

## Remediation Priority Guide

| Priority | Categories | Risk |
|----------|-----------|------|
| HIGH — Immediate action | A01 Broken Access Control, A03 Injection, A07 Authentication Failures | Direct data exposure risk |
| MEDIUM — Short-term action | A02 Cryptographic Failures, A05 Security Misconfiguration, A06 Outdated Components | Resolved by patching/reconfiguration |
| LOW — Long-term planning | A04 Insecure Design, A08 Integrity Failures, A09 Logging Failures, A10 SSRF | Process/architecture improvements |

Full OWASP Top 10 reference: https://owasp.org/Top10/
