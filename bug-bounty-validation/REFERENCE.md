# Reference: bug-bounty-validation

## Always-Rejected List

Findings matching any entry below are an automatic KILL regardless of technical quality.

| # | Finding Type |
|---|-------------|
| 1 | Self-XSS with no demonstrated chain to another user's session |
| 2 | Missing security best practices with no demonstrated impact (e.g., no HSTS header, no X-Frame-Options, SPF record not strict) |
| 3 | Theoretical attacks without a working proof-of-concept |
| 4 | Scanner output copy-pasted without manual verification of exploitability |
| 5 | Issues requiring physical access to the target device |
| 6 | Volumetric denial-of-service (rate limit abuse, resource exhaustion via HTTP flood) |
| 7 | Social engineering attacks against company employees |
| 8 | Findings on assets that are explicitly out of scope |
| 9 | Vulnerabilities in third-party software the company does not control |
| 10 | Login/logout CSRF without demonstrated impact (most programs exempt this) |
| 11 | Password policy weakness (minimum length, no complexity requirement) |
| 12 | Username/email enumeration via response timing on public-facing login only (unless the program is in a sector where user enumeration is High, e.g., healthcare) |
| 13 | Clickjacking on pages without sensitive state-changing actions |
| 14 | SSL/TLS version issues on assets that are CDN-terminated |

---

## Conditionally-Valid-With-Chain Table

Findings that are invalid standalone but can reach valid (often high) severity when chained with a partner vulnerability.

| Finding Alone | Standalone Verdict | Chain Partner Needed | Chained Verdict |
|---------------|--------------------|----------------------|-----------------|
| Open Redirect | N/A | OAuth state hijack | High |
| Open Redirect | N/A | SSRF via redirect | High/Critical |
| Open Redirect | N/A | Phishing + token theft | Medium |
| Self-XSS | N/A | CSRF to trigger payload | Medium/High |
| Self-XSS | N/A | Log injection + view | Medium |
| Clickjacking | N/A | State-changing action on page | Medium |
| CSRF (low impact action) | Low/N/A | Admin action endpoint | High |
| CSRF (low impact action) | Low/N/A | Account takeover flow | Critical |
| Subdomain takeover (blank) | Medium | Auth cookie scope leak | High/Critical |
| IDOR (read-only, non-PII) | Low/Medium | PII endpoint | High |
| IDOR (read-only, non-PII) | Low/Medium | Write/delete capability | High/Critical |
| Stored HTML injection | Low | Script execution context | High (XSS) |
| Server error message | Informational | SQL syntax visible | Medium (SQLi signal) |
| Rate limit absent (login) | Low | No account lockout + weak passwords | High |

---

## CVSS 3.1 Quick Reference

### Metric Weights

| Metric | Value | Description | Weight |
|--------|-------|-------------|--------|
| **Attack Vector (AV)** | N | Network (exploitable remotely) | +0.85 |
| | A | Adjacent network | +0.62 |
| | L | Local (requires local access) | +0.55 |
| | P | Physical | +0.20 |
| **Attack Complexity (AC)** | L | Low (no special conditions) | +0.77 |
| | H | High (race, specific config needed) | +0.44 |
| **Privileges Required (PR)** | N | None | +0.85 |
| | L | Low (regular user) | +0.62 (0.50 if Scope Changed) |
| | H | High (admin) | +0.27 (0.50 if Scope Changed) |
| **User Interaction (UI)** | N | None | +0.85 |
| | R | Required (victim must click) | +0.62 |
| **Scope (S)** | U | Unchanged (impact limited to component) | — |
| | C | Changed (impact crosses security boundary) | — |
| **Confidentiality / Integrity / Availability (C/I/A)** | H | High (full loss) | +0.56 |
| | L | Low (partial loss) | +0.22 |
| | N | None | +0.00 |

### Severity Bands

| Severity | CVSS Range | Typical Profile | Example |
|----------|-----------|-----------------|---------|
| Critical | 9.0 – 10.0 | AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H | Unauthenticated RCE, pre-auth account takeover |
| High | 7.0 – 8.9 | AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N | Authenticated IDOR exposing full user PII, stored XSS with ATO chain |
| Medium | 4.0 – 6.9 | AV:N / AC:L / PR:L / UI:R / S:U / C:L / I:L / A:N | Reflected XSS requiring user interaction, IDOR on non-PII data |
| Low | 0.1 – 3.9 | AV:N / AC:H / PR:L / UI:R / S:U / C:L / I:N / A:N | Information disclosure of non-sensitive data, minor logic flaw with no escalation path |

### Score Sanity Checks

| Symptom | Correction |
|---------|-----------|
| Assigned Critical but requires user login | Downgrade PR from N to L |
| Assigned High but impact is read-only on non-PII | Downgrade C from H to L |
| Assigned High but requires victim to click a link | Set UI:R |
| Score does not match program's severity map | Use program's map if it is more restrictive |
