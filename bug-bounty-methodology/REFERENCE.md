# Reference: bug-bounty-methodology

## Decision Flow Routing Table

Maps observed input types to vulnerability classes and related skills.

| Input type observed | Vulnerability class to test | Related skill |
|---------------------|-----------------------------|---------------|
| ID parameter (`user_id`, `order_id`) | IDOR | `web-vuln-idor` |
| URL / webhook input | SSRF | `web-vuln-ssrf` |
| Price / quantity / coupon | Business logic | `web-vuln-business-logic` |
| Text reflected in page | XSS | — |
| Login / 2FA / password reset | Auth bypass | — |
| Template / wiki editor | SSTI | — |

## Escalation Decision Tree

Maps an initial low-impact finding to a higher-severity attack chain.

| Finding type | Escalation path | Target severity |
|--------------|-----------------|-----------------|
| XSS found | Steal cookie/token → session hijack → ATO | Critical/High |
| IDOR found | Read PII or write data → chain to ATO | High |
| SSRF found | Reach cloud metadata → extract IAM keys → RCE | Critical |
| SQLi found | Extract password hashes → `INTO OUTFILE` for webshell | Critical |

**Minimize attack prerequisites** (for severity scoring):

| User interaction required | Typical severity |
|---------------------------|-----------------|
| 0 clicks | Critical |
| 1 email click | High |
| Requires phishing | Medium |

## Time Management and Anti-Pattern Advice

### Rotation rules

- **20-minute rule**: If an endpoint shows no progress in 20 minutes, rotate to the next one.
- **45-minute rule**: Hard stop — rabbit hole detected. Move on and add to "investigate later" list.

### Anti-patterns to avoid

| Anti-pattern | Why it hurts | Correction |
|--------------|-------------|------------|
| Program hopping | Prevents deep understanding of any one target | Stick with one target a minimum of 30 hours |
| Tool-only hunting | Automation finds duplicates; manual finds unique bugs | Balance automation with manual testing |
| No session goal | Unfocused time leads to low-value findings | Always define `BB_SESSION_GOAL` before starting |
| Ignoring "weird" behaviors | Anomalies are future chaining gadgets | Log all anomalies even if not immediately exploitable |

### A→B Signal

After finding one bug, apply the A→B signal: the same developer likely made more mistakes nearby. Hunt siblings for 20 minutes before moving on.
