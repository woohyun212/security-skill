# Reference: cors-check

## Risk Assessment Criteria

Severity levels for CORS misconfiguration findings, with remediation guidance.

| Severity | Condition | Impact |
|----------|-----------|--------|
| **CRITICAL** | `ACAO` reflects request `Origin` + `ACAC: true` | Attacker can execute authenticated API requests cross-site (credential theft) |
| **HIGH** | `ACAO: null` + `ACAC: true` | Exploitable from sandboxed iframes or local files |
| **MEDIUM** | `ACAO` reflects request `Origin` (no `ACAC`) | Dangerous if the response contains sensitive data |
| **LOW / INFO** | `ACAO: *` (wildcard, no `ACAC`) | May be intentional for public APIs; not directly exploitable |

## Remediation Guidance

- Fix allowed Origins to an explicit whitelist — do not dynamically reflect the incoming `Origin` header.
- Do not use wildcard (`*`) when `Access-Control-Allow-Credentials: true` is set.
- Disallow `null` as an allowed Origin.
- Add `Vary: Origin` response header to prevent cache poisoning attacks.
