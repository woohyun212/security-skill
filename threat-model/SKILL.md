---
name: threat-model
description: Threat modeling using STRIDE, DREAD, PASTA, and Attack Trees frameworks
license: MIT
metadata:
  category: compliance
  locale: en
  phase: v1
---

## What this skill does

Guides a structured threat modeling exercise for a target system using industry-standard frameworks: STRIDE (threat categorization), DREAD (risk scoring), PASTA (process-driven methodology), and Attack Trees (attack decomposition). Produces a threat catalog with MITRE ATT&CK mappings, a risk matrix, and a prioritized mitigation roadmap.

## When to use

- During system design or architecture review to identify security risks before implementation
- When preparing for a security audit or compliance assessment that requires documented threat analysis
- When onboarding a new system into a security program and baseline threat coverage is needed
- When a significant feature or infrastructure change warrants re-evaluation of the attack surface

## Prerequisites

- No external tools required (methodology/checklist-based)
- Access to system architecture diagrams, data flow diagrams (DFDs), or equivalent documentation
- Knowledge of the system's technology stack, trust boundaries, and data sensitivity levels
- (Optional) MITRE ATT&CK reference: https://attack.mitre.org

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `SYSTEM_NAME` | Name of the system under review | `Payment API v3` |
| `SYSTEM_TYPE` | Type of system | `web-app` / `api` / `microservice` / `infrastructure` |
| `TECH_STACK` | Technology stack | `Node.js, PostgreSQL, Redis, AWS ECS` |
| `DATA_SENSITIVITY` | Highest data classification in scope | `PII` / `PCI` / `internal` / `public` |
| `REVIEW_SCOPE` | Boundaries of the review | `All external-facing endpoints and auth flows` |

## Workflow

### Step 1: System Decomposition

Identify what needs protecting before identifying threats. Collect the following information about the target system.

**Asset Inventory**

Document all assets within scope using this template:

```markdown
## Asset Inventory

| Asset ID | Asset Name | Type | Data Classification | Owner |
|----------|------------|------|---------------------|-------|
| A-001    | User credentials store | Data | PII / Confidential | Auth team |
| A-002    | Payment transaction records | Data | PCI DSS | Payments team |
| A-003    | Authentication service | Service | N/A | Platform team |
| A-004    | Admin dashboard | Interface | Internal | Ops team |
```

**Trust Boundary Mapping**

Enumerate trust zones and the boundaries between them:

```markdown
## Trust Boundaries

| Boundary ID | From Zone | To Zone | Protocol | Authentication Required |
|-------------|-----------|---------|----------|------------------------|
| TB-001 | Internet (untrusted) | Web tier (DMZ) | HTTPS/443 | No (public) |
| TB-002 | Web tier (DMZ) | App tier (internal) | HTTP/8080 | mTLS |
| TB-003 | App tier (internal) | Database tier | TCP/5432 | Password + TLS |
| TB-004 | App tier (internal) | Admin dashboard | HTTPS/443 | MFA required |
```

**Entry Point Enumeration**

List all external-facing entry points:

```markdown
## Entry Points

| EP ID | Entry Point | Protocol | Auth Mechanism | Notes |
|-------|-------------|----------|----------------|-------|
| EP-001 | POST /api/v1/login | HTTPS | Username + password | Rate limited |
| EP-002 | GET /api/v1/users/{id} | HTTPS | JWT Bearer | Authenticated only |
| EP-003 | POST /api/v1/payments | HTTPS | JWT Bearer + HMAC | PCI scope |
| EP-004 | Admin UI /admin/* | HTTPS | SSO + MFA | Internal network only |
```

**Data Flow Diagram (DFD) Summary**

Describe the primary data flows as a numbered list if a visual DFD is unavailable:

```markdown
## Key Data Flows

1. User submits credentials → Web tier → Auth service → Credentials DB → JWT issued
2. Authenticated user submits payment → Web tier → Payment service → Payment processor (external) → Transaction DB
3. Admin queries reports → Admin UI → Reporting service → Read replica DB
```

### Step 2: Threat Identification (STRIDE)

Apply the STRIDE model to each DFD element (processes, data stores, data flows, external entities) and each trust boundary crossing. For each threat identified, create a catalog entry using the T-NNN format.

**STRIDE Categories Reference**

| Category | Code | Question to ask |
|----------|------|-----------------|
| Spoofing | S | Can an attacker impersonate a user, service, or component? |
| Tampering | T | Can an attacker modify data in transit or at rest? |
| Repudiation | R | Can an actor deny performing an action without detection? |
| Information Disclosure | I | Can an attacker access data they are not authorized to see? |
| Denial of Service | D | Can an attacker degrade or disable service availability? |
| Elevation of Privilege | E | Can an attacker gain permissions beyond what was granted? |

**Threat Catalog Template**

Create one entry per identified threat:

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

---

### T-002: SQL injection via unsanitized payment amount parameter

| Field | Value |
|-------|-------|
| STRIDE Category | Tampering (T), Information Disclosure (I) |
| Affected Asset | A-002 Payment transaction records |
| Affected Entry Point | EP-003 |
| Attack Vector | Malformed `amount` field bypasses numeric validation and is concatenated into a raw SQL query |
| Impact | Unauthorized modification of transaction records; potential full DB dump |
| Likelihood | Low — parameterized queries are used in most paths but one legacy handler is not |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application |
| Existing Controls | ORM used for most queries; WAF in front of web tier |
| Recommended Controls | Audit all raw query usages; enforce parameterized queries; add SQLi-specific WAF rule |
```

Repeat this template for every threat identified across all STRIDE categories and DFD elements.

### Step 3: Threat Prioritization (DREAD Scoring)

Score each threat in the catalog using the DREAD model. Each dimension is scored 1–10; the total DREAD score is the average, rounded to one decimal place.

**DREAD Dimensions**

| Dimension | Description | Low (1–3) | Medium (4–6) | High (7–10) |
|-----------|-------------|-----------|--------------|-------------|
| Damage | Impact if exploited | Minimal data exposure | Significant data loss or service degradation | Full compromise, data destruction, or RCE |
| Reproducibility | How easily can the attack be repeated | Requires rare conditions | Repeatable with effort | Trivially repeatable |
| Exploitability | Skill/resources required to exploit | Nation-state level | Skilled attacker | Script kiddie / automated tool |
| Affected Users | Breadth of impact | Single user | Group of users | All users or critical systems |
| Discoverability | How easy is it to find the vulnerability | Requires deep source code review | Discoverable via black-box testing | Visible in public documentation or response headers |

**DREAD Scoring Table**

```markdown
## DREAD Risk Scores

| Threat ID | Description | Damage | Repro | Exploit | Affected | Discover | DREAD Score | Risk Level |
|-----------|-------------|--------|-------|---------|----------|----------|-------------|------------|
| T-001 | JWT forgery | 9 | 7 | 6 | 10 | 4 | 7.2 | HIGH |
| T-002 | SQL injection | 9 | 8 | 7 | 8 | 5 | 7.4 | HIGH |
| T-003 | ... | | | | | | | |
```

**Risk Level Thresholds**

| DREAD Score | Risk Level | Action |
|-------------|------------|--------|
| 8.0 – 10.0 | CRITICAL | Immediate remediation required; block release |
| 6.0 – 7.9 | HIGH | Remediate before next release |
| 4.0 – 5.9 | MEDIUM | Schedule remediation within 30 days |
| 2.0 – 3.9 | LOW | Track in backlog; remediate within 90 days |
| 1.0 – 1.9 | INFO | Accept risk or monitor |

**CVSS Mapping (optional)**

For threats that require formal CVE-style scoring, calculate a CVSS v3.1 Base Score alongside DREAD using the NVD calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

### Step 4: Mitigation Design

For each HIGH and CRITICAL threat, design concrete mitigations applying defense-in-depth principles.

**Mitigation Roadmap Template**

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

---

### T-002: SQL injection — HIGH (DREAD 7.4)

**Immediate**
- [ ] Audit all database access code for raw query usage (`grep -r "execute(" src/`)
- [ ] Replace identified raw queries with parameterized equivalents
- [ ] Add SAST rule in CI to flag string concatenation in SQL contexts

**Short-term**
- [ ] Enable WAF managed rule group for SQL injection (AWS WAF: AWSManagedRulesSQLiRuleSet)

**Residual Risk**: ORM version vulnerabilities — mitigated by `dependency-audit` skill on a monthly cadence
```

**Risk Matrix**

Produce a 5x5 risk matrix to visualize the portfolio of identified threats:

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

## Done when

- System decomposition is complete: assets, trust boundaries, entry points, and data flows documented
- STRIDE analysis has been applied to every DFD element and trust boundary
- Every identified threat has a T-NNN catalog entry with STRIDE category, attack vector, impact, MITRE ATT&CK mapping, and existing/recommended controls
- Every threat has a DREAD score and risk level assignment
- A mitigation roadmap exists for all HIGH and CRITICAL threats
- A risk matrix summarizes the full threat portfolio
- Residual risks are explicitly acknowledged

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Incomplete asset inventory | System documentation missing or outdated | Interview system owner; reverse-engineer from network diagrams or source code |
| STRIDE produces no threats | Analysis too surface-level | Apply STRIDE to each individual data flow, not just the system as a whole |
| DREAD scores inconsistent across reviewers | Subjective scoring | Calibrate with a reference threat (e.g., score a known CVE before scoring new threats) |
| Mitigation roadmap not actionable | Controls described too abstractly | Each control should name a specific technology, configuration, or code change |
| MITRE ATT&CK mapping unclear | Unfamiliarity with the framework | Use the ATT&CK Navigator at https://mitre-attack.github.io/attack-navigator/ to search by technique |

## Notes

- This skill covers the four most common threat modeling frameworks. For new systems, start with STRIDE + DREAD. Add PASTA for regulatory-sensitive contexts (PCI DSS, HIPAA) where a full process trace is required.
- Threat models are living documents. Re-run this skill after major architecture changes, new external integrations, or changes to data classification.
- Attack Trees are best suited for high-value specific threats (e.g., "attacker gains admin access"). Construct a tree by placing the attacker's goal at the root and decomposing it into AND/OR sub-goals until leaf nodes are concrete, testable attack steps.
- Pair this skill with `owasp-check` for web applications and `dependency-audit` for supply chain threats to achieve broader coverage.
- MITRE ATT&CK Enterprise matrix reference: https://attack.mitre.org/matrices/enterprise/
