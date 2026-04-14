# Reference: threat-model

## STRIDE Categories Reference Table

| Category | Code | Question to ask |
|----------|------|-----------------|
| Spoofing | S | Can an attacker impersonate a user, service, or component? |
| Tampering | T | Can an attacker modify data in transit or at rest? |
| Repudiation | R | Can an actor deny performing an action without detection? |
| Information Disclosure | I | Can an attacker access data they are not authorized to see? |
| Denial of Service | D | Can an attacker degrade or disable service availability? |
| Elevation of Privilege | E | Can an attacker gain permissions beyond what was granted? |

---

## DREAD Dimensions Reference Table

| Dimension | Description | Low (1–3) | Medium (4–6) | High (7–10) |
|-----------|-------------|-----------|--------------|-------------|
| Damage | Impact if exploited | Minimal data exposure | Significant data loss or service degradation | Full compromise, data destruction, or RCE |
| Reproducibility | How easily can the attack be repeated | Requires rare conditions | Repeatable with effort | Trivially repeatable |
| Exploitability | Skill/resources required to exploit | Nation-state level | Skilled attacker | Script kiddie / automated tool |
| Affected Users | Breadth of impact | Single user | Group of users | All users or critical systems |
| Discoverability | How easy is it to find the vulnerability | Requires deep source code review | Discoverable via black-box testing | Visible in public documentation or response headers |

**Risk Level Thresholds**

| DREAD Score | Risk Level | Action |
|-------------|------------|--------|
| 8.0 – 10.0 | CRITICAL | Immediate remediation required; block release |
| 6.0 – 7.9 | HIGH | Remediate before next release |
| 4.0 – 5.9 | MEDIUM | Schedule remediation within 30 days |
| 2.0 – 3.9 | LOW | Track in backlog; remediate within 90 days |
| 1.0 – 1.9 | INFO | Accept risk or monitor |

---

## Markdown Templates

### Asset Inventory Template

```markdown
## Asset Inventory

| Asset ID | Asset Name | Type | Data Classification | Owner |
|----------|------------|------|---------------------|-------|
| A-001    | User credentials store | Data | PII / Confidential | Auth team |
| A-002    | Payment transaction records | Data | PCI DSS | Payments team |
| A-003    | Authentication service | Service | N/A | Platform team |
| A-004    | Admin dashboard | Interface | Internal | Ops team |
```

### Trust Boundaries Template

```markdown
## Trust Boundaries

| Boundary ID | From Zone | To Zone | Protocol | Authentication Required |
|-------------|-----------|---------|----------|------------------------|
| TB-001 | Internet (untrusted) | Web tier (DMZ) | HTTPS/443 | No (public) |
| TB-002 | Web tier (DMZ) | App tier (internal) | HTTP/8080 | mTLS |
| TB-003 | App tier (internal) | Database tier | TCP/5432 | Password + TLS |
| TB-004 | App tier (internal) | Admin dashboard | HTTPS/443 | MFA required |
```

### Entry Points Template

```markdown
## Entry Points

| EP ID | Entry Point | Protocol | Auth Mechanism | Notes |
|-------|-------------|----------|----------------|-------|
| EP-001 | POST /api/v1/login | HTTPS | Username + password | Rate limited |
| EP-002 | GET /api/v1/users/{id} | HTTPS | JWT Bearer | Authenticated only |
| EP-003 | POST /api/v1/payments | HTTPS | JWT Bearer + HMAC | PCI scope |
| EP-004 | Admin UI /admin/* | HTTPS | SSO + MFA | Internal network only |
```

### Threat Catalog Entry Template

```markdown
## Threat Catalog

### T-001: JWT token forgery via weak signing secret

| Field | Value |
|-------|-------|
| STRIDE Category | Spoofing (S) |
| Affected Asset | A-003 Authentication service |
| Affected Entry Point | EP-001, EP-002, EP-003 |
| Attack Vector | An attacker who discovers or brute-forces a weak HMAC secret can forge valid JWTs and authenticate as any user |
| Impact | Full authentication bypass; access to all authenticated endpoints |
| Likelihood | Medium — requires secret exposure or weak secret selection |
| MITRE ATT&CK | T1550.001 Use Alternate Authentication Material: Application Access Token |
| Existing Controls | JWT expiry enforced (15 min); secret stored in environment variable |
| Recommended Controls | Rotate to RS256 (asymmetric); store private key in KMS; add JWT `jti` claim blacklist on logout |
```

### DREAD Scoring Table Template

```markdown
## DREAD Risk Scores

| Threat ID | Description | Damage | Repro | Exploit | Affected | Discover | DREAD Score | Risk Level |
|-----------|-------------|--------|-------|---------|----------|----------|-------------|------------|
| T-001 | JWT forgery | 9 | 7 | 6 | 10 | 4 | 7.2 | HIGH |
| T-002 | SQL injection | 9 | 8 | 7 | 8 | 5 | 7.4 | HIGH |
| T-003 | ... | | | | | | | |
```

### Mitigation Roadmap Template

```markdown
## Mitigation Roadmap

### T-001: JWT token forgery — HIGH (DREAD 7.2)

**Immediate (Sprint N)**
- [ ] Rotate JWT signing to RS256; generate 4096-bit RSA key pair
- [ ] Store private key in AWS KMS; application retrieves via IAM role
- [ ] Add integration test asserting HS256-signed tokens are rejected

**Short-term (within 30 days)**
- [ ] Implement `jti` claim with Redis blacklist for token invalidation on logout
- [ ] Add anomaly detection alert for tokens issued from unusual IP ranges

**Long-term**
- [ ] Evaluate PASETO tokens as a replacement for JWT across all services

**Defense-in-Depth Layers Applied**
- Preventive: Key type enforcement (RS256)
- Detective: Anomaly alerting on suspicious JWT origins
- Corrective: Token blacklist for immediate revocation
```

### Risk Matrix Template

```markdown
## Risk Matrix (Likelihood vs. Impact)

             | Very Low | Low | Medium | High | Critical |
-------------|----------|-----|--------|------|----------|
Very Likely  |          |     |        |      |          |
Likely       |          |     |        | T-001|          |
Possible     |          |     |        | T-002|          |
Unlikely     |          |     |        |      |          |
Rare         |          |     |        |      |          |
```
