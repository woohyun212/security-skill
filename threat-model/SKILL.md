---
name: threat-model
description: Structured threat modeling producing threat catalog with STRIDE categorization, DREAD risk scores, and prioritized mitigation roadmap
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

> **Reference**: See [REFERENCE.md](REFERENCE.md) for asset inventory, trust boundaries, and entry points markdown templates.

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

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the STRIDE categories reference table and threat catalog entry template.

Repeat the threat catalog template for every threat identified across all STRIDE categories and DFD elements.

### Step 3: Threat Prioritization (DREAD Scoring)

Score each threat in the catalog using the DREAD model. Each dimension is scored 1–10; the total DREAD score is the average, rounded to one decimal place.

> **Reference**: See [REFERENCE.md](REFERENCE.md) for DREAD dimensions, scoring table template, and risk level thresholds.

**CVSS Mapping (optional)**

For threats that require formal CVE-style scoring, calculate a CVSS v3.1 Base Score alongside DREAD using the NVD calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

### Step 4: Mitigation Design

For each HIGH and CRITICAL threat, design concrete mitigations applying defense-in-depth principles.

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the mitigation roadmap template and 5x5 risk matrix template.

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
