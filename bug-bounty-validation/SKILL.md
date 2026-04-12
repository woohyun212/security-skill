---
name: bug-bounty-validation
description: Bug bounty finding validation with 7-Question Gate and pre-submission quality checklist
license: MIT
metadata:
  category: compliance
  locale: en
  phase: v1
---

## What this skill does

Provides a structured decision framework for validating bug bounty findings before submission. Runs a sequential gate system — 7-Question Gate, Always-Rejected List, Chain Requirement Evaluation, 4 Pre-Submission Gates, and CVSS 3.1 severity assessment — to produce a final verdict of SUBMIT, KILL, NEEDS CHAIN, or NEEDS IMPROVEMENT. Eliminates wasted submissions by catching invalid, out-of-scope, or low-quality reports before they reach the program.

## When to use

- After discovering a potential vulnerability and before writing the full report
- When unsure whether a finding is worth submitting
- When a finding seems valid but impact is borderline
- When you have a low-severity finding and want to know if chaining elevates it
- When a triage response came back "Informational" or "N/A" and you want to understand why
- When reviewing a draft report for quality before final submission

## Prerequisites

- A potential finding with at least one HTTP request/response pair demonstrating the behavior
- Knowledge of the target program's scope page (assets, exclusions, accepted vulnerability classes)
- Access to the program's policy page on HackerOne, Bugcrowd, Intigriti, or equivalent platform
- No external tools are required — this skill is a decision framework

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `BV_FINDING` | Yes | Short description of the vulnerability (e.g., "IDOR on /api/orders/ID allows reading other users' orders") |
| `BV_ASSET` | Yes | Full domain or asset where the finding was observed (e.g., `api.example.com`) |
| `BV_VULN_CLASS` | Yes | Vulnerability class (e.g., IDOR, XSS, SSRF, Open Redirect, CSRF) |
| `BV_POC_STEPS` | Yes | Number of reproduction steps documented |
| `BV_IMPACT` | Yes | One sentence describing the concrete business impact |
| `BV_AUTH_REQUIRED` | Yes | `none`, `user`, or `admin` — minimum privilege level required to exploit |
| `BV_PROGRAM_SCOPE_URL` | Optional | URL to the program's scope page for cross-reference |
| `BV_CHAIN_PARTNER` | Optional | Second vulnerability you can chain with this finding (leave blank if standalone) |

## Workflow

### Step 1: Run the 7-Question Gate

Answer YES or NO to each question. All 7 must be YES to continue. Any NO is an immediate KILL.

```
7-QUESTION GATE
===============
Q1: Do you have a real HTTP proof-of-concept — not just theoretical reasoning?
    YES = you can show a request/response pair where the bug is triggered
    NO  -> KILL. Document the behavior as a research note and move on.

Q2: Is the impact accepted by the program's policy?
    YES = the program explicitly lists this vuln class as in-scope or does not exclude it
    NO  -> KILL. Policy exclusions are non-negotiable regardless of technical severity.

Q3: Is the affected asset explicitly in scope?
    YES = the asset (domain, subdomain, API endpoint) appears in the program's in-scope list
    NO  -> KILL. Out-of-scope submissions damage your reputation and waste triage time.

Q4: Can it be exploited WITHOUT privileged or admin access?
    YES = a regular user account (or no account) is sufficient to trigger the bug
    NO  -> KILL unless the program specifically rewards admin-perspective findings.

Q5: Is this NOT known or documented behavior?
    YES = the behavior is not described in the app's documentation, help center, or changelogs
    NO  -> KILL. Intentional behavior is not a vulnerability.

Q6: Can you prove impact beyond "technically possible"?
    YES = you can demonstrate actual data read, data written, account taken over, or equivalent
    NO  -> KILL or downgrade to NEEDS IMPROVEMENT (add a concrete impact demonstration).

Q7: Is this NOT on the always-rejected list?
    YES = the finding does not match any entry in the always-rejected list (see Step 2)
    NO  -> KILL. Always-rejected findings are rejected regardless of quality.

GATE RESULT: Count YES answers.
  7/7 YES -> Proceed to Step 2
  Any NO  -> KILL. Do not submit.
```

### Step 2: Check the always-rejected list

Compare the finding against each entry. A match is an automatic KILL regardless of Step 1 results.

```
ALWAYS-REJECTED LIST
====================
[ ] Self-XSS with no demonstrated chain to another user's session
[ ] Missing security best practices with no demonstrated impact
    (e.g., no HSTS header, no X-Frame-Options, SPF record not strict)
[ ] Theoretical attacks without a working proof-of-concept
[ ] Scanner output copy-pasted without manual verification of exploitability
[ ] Issues requiring physical access to the target device
[ ] Volumetric denial-of-service (rate limit abuse, resource exhaustion via HTTP flood)
[ ] Social engineering attacks against company employees
[ ] Findings on assets that are explicitly out of scope
[ ] Vulnerabilities in third-party software the company does not control
[ ] Login/logout CSRF without demonstrated impact (most programs exempt this)
[ ] Password policy weakness (minimum length, no complexity requirement)
[ ] Username/email enumeration via response timing on public-facing login only
    (unless the program is in a sector where user enumeration is High, e.g., healthcare)
[ ] Clickjacking on pages without sensitive state-changing actions
[ ] SSL/TLS version issues on assets that are CDN-terminated

EVALUATION:
  0 matches -> Proceed to Step 3
  1+ matches -> KILL. Note which entry matched and why.
```

### Step 3: Evaluate chain requirement

Some findings are invalid standalone but valid (and often high severity) when chained. Identify the finding's chain status before scoring severity.

```
CONDITIONALLY-VALID-WITH-CHAIN TABLE
=====================================
Finding alone              | Standalone verdict | Chain partner needed      | Chained verdict
---------------------------|-------------------|---------------------------|----------------
Open Redirect              | N/A               | OAuth state hijack        | High
                           |                   | SSRF via redirect         | High/Critical
                           |                   | Phishing + token theft    | Medium
Self-XSS                   | N/A               | CSRF to trigger payload   | Medium/High
                           |                   | Log injection + view      | Medium
Clickjacking               | N/A               | State-changing action on page | Medium
CSRF (low impact action)   | Low/N/A           | Admin action endpoint     | High
                           |                   | Account takeover flow     | Critical
Subdomain takeover (blank) | Medium            | Auth cookie scope leak    | High/Critical
IDOR (read-only, non-PII)  | Low/Medium        | PII endpoint              | High
                           |                   | Write/delete capability   | High/Critical
Stored HTML injection      | Low               | Script execution context  | High (XSS)
Server error message        | Informational     | SQL syntax visible        | Medium (SQLi signal)
Rate limit absent (login)  | Low               | No account lockout + weak passwords | High

EVALUATION:
  Finding is valid standalone         -> Proceed to Step 4
  Finding requires a chain partner    -> Check BV_CHAIN_PARTNER
    BV_CHAIN_PARTNER is set           -> Document chain, proceed to Step 4 with combined class
    BV_CHAIN_PARTNER is not set       -> NEEDS CHAIN. Research chain partner before submitting.
  Finding is N/A even with chain      -> KILL.
```

### Step 4: Run the 4 pre-submission gates

Each gate has a PASS threshold. Failing any gate produces NEEDS IMPROVEMENT, not KILL — fix the gap and re-run.

```
PRE-SUBMISSION GATE 1: TECHNICAL
=================================
[ ] PoC works in a clean browser profile or fresh session (not just your existing session)
[ ] PoC works with cookies/tokens from a second test account (confirms it is not self-only)
[ ] Minimum 3 reproduction steps documented (numbered, unambiguous)
[ ] Each step specifies: HTTP method, endpoint, headers, body, and expected vs. actual response
[ ] PoC does not depend on a race condition you cannot reliably reproduce (if it does, note success rate)

GATE 1 RESULT:
  5/5 checked -> PASS
  Missing items -> NEEDS IMPROVEMENT. Complete all items before proceeding.

PRE-SUBMISSION GATE 2: SCOPE
==============================
[ ] Confirm the exact domain/IP is listed on the scope page (wildcard *.example.com covers subdomains)
[ ] Confirm the vulnerability class is not in the program's explicit exclusion list
[ ] Confirm the endpoint is not a third-party service (check CNAME, Shodan, response headers)
[ ] If the target is a mobile app, confirm the app version tested matches the current release

GATE 2 RESULT:
  4/4 checked -> PASS
  Missing items -> NEEDS IMPROVEMENT. Verify scope before proceeding.

PRE-SUBMISSION GATE 3: IMPACT
==============================
[ ] Written a one-sentence business impact statement (who is affected, what data or action, at what scale)
[ ] Calculated CVSS 3.1 score (see Step 5) and it is consistent with the demonstrated impact
[ ] Impact statement references a concrete artifact: data exfiltrated, account compromised, service disrupted
[ ] Impact is proportional to actual exploitation — not the theoretical worst case

GATE 3 RESULT:
  4/4 checked -> PASS
  Missing items -> NEEDS IMPROVEMENT. Strengthen impact evidence before proceeding.

PRE-SUBMISSION GATE 4: QUALITY
================================
[ ] Report follows the platform's template structure (Summary, Steps to Reproduce, Impact, CVSS)
[ ] Screenshots or HTTP logs (Burp/Caido export) are attached for every key step
[ ] Report does not contain actual PII of real users (use test accounts only; blur or redact any real data)
[ ] Technical jargon is explained in one sentence where used (program staff may not be senior engineers)
[ ] Title is ≤ 120 characters and contains: vuln class + asset + one-line impact
    Good: "IDOR on /api/v2/orders allows unauthenticated read of any user's order history"
    Bad: "Security issue found"

GATE 4 RESULT:
  5/5 checked -> PASS
  Missing items -> NEEDS IMPROVEMENT. Fix quality gaps before proceeding.

OVERALL GATE RESULT:
  Gates 1-4 all PASS -> Proceed to Step 5
  Any gate NEEDS IMPROVEMENT -> Fix all flagged items, re-run that gate, then proceed
```

### Step 5: Assess CVSS 3.1 severity

Use the quick reference below to calculate a score. Assign the score that matches what you can actually demonstrate, not the theoretical maximum.

```
CVSS 3.1 QUICK REFERENCE
==========================
Attack Vector (AV)
  N = Network (exploitable remotely)        +0.85 weight
  A = Adjacent network                      +0.62
  L = Local (requires local access)         +0.55
  P = Physical                              +0.20

Attack Complexity (AC)
  L = Low (no special conditions)           +0.77
  H = High (race, specific config needed)   +0.44

Privileges Required (PR)
  N = None                                  +0.85
  L = Low (regular user)                    +0.62 (0.50 if Scope Changed)
  H = High (admin)                          +0.27 (0.50 if Scope Changed)

User Interaction (UI)
  N = None                                  +0.85
  R = Required (victim must click)          +0.62

Scope (S)
  U = Unchanged (impact limited to component) 
  C = Changed (impact crosses security boundary)

Confidentiality / Integrity / Availability Impact (C/I/A)
  H = High (full loss)                      +0.56
  L = Low (partial loss)                    +0.22
  N = None                                  +0.00

SEVERITY BANDS:
  Critical : CVSS 9.0 – 10.0
    Typical profile: AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H
    Example: Unauthenticated RCE, pre-auth account takeover

  High     : CVSS 7.0 – 8.9
    Typical profile: AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N
    Example: Authenticated IDOR exposing full user PII, stored XSS with ATO chain

  Medium   : CVSS 4.0 – 6.9
    Typical profile: AV:N / AC:L / PR:L / UI:R / S:U / C:L / I:L / A:N
    Example: Reflected XSS requiring user interaction, IDOR on non-PII data

  Low      : CVSS 0.1 – 3.9
    Typical profile: AV:N / AC:H / PR:L / UI:R / S:U / C:L / I:N / A:N
    Example: Information disclosure of non-sensitive data, minor logic flaw with no escalation path

SCORE SANITY CHECKS:
  Assigned Critical but requires user login? -> Downgrade PR from N to L.
  Assigned High but impact is read-only on non-PII? -> Downgrade C from H to L.
  Assigned High but requires victim to click a link? -> Set UI:R.
  Score does not match program's severity map? -> Use program's map if it is more restrictive.
```

### Step 6: Output final verdict

Combine all gate results into a single verdict.

```
FINAL VERDICT LOGIC
====================

IF any 7-Question Gate answer is NO:
  -> VERDICT: KILL
  -> Reason: [which question failed]
  -> Action: Do not submit. Document as research note.

IF any Always-Rejected List item matched:
  -> VERDICT: KILL
  -> Reason: [which list entry matched]
  -> Action: Do not submit. Delete draft to avoid accidental submission.

IF finding requires a chain partner AND BV_CHAIN_PARTNER is not set:
  -> VERDICT: NEEDS CHAIN
  -> Reason: Standalone finding does not meet minimum impact threshold
  -> Action: Research chain partner. Re-run from Step 3 once chain is identified.

IF any Pre-Submission Gate is NEEDS IMPROVEMENT:
  -> VERDICT: NEEDS IMPROVEMENT
  -> Reason: [list each failed gate item]
  -> Action: Fix all flagged items. Re-run failed gate only. Do not re-run full validation.

IF all gates PASS and CVSS score is calculated:
  -> VERDICT: SUBMIT
  -> Severity: [Critical / High / Medium / Low] (CVSS [score])
  -> Report title: [BV_FINDING — one line, ≤ 120 characters]
  -> Checklist before sending:
       [ ] PoC request/response attached
       [ ] Reproduction steps numbered and complete
       [ ] Impact statement written
       [ ] CVSS score included in report
       [ ] No real user PII in report
       [ ] Platform template followed

VERDICT SUMMARY TABLE
======================
Verdict            | Meaning                                     | Next action
-------------------|---------------------------------------------|---------------------------
SUBMIT             | Finding is valid, scoped, impactful, quality| Submit report now
KILL               | Finding is invalid or out of scope           | Discard, log as research note
NEEDS CHAIN        | Valid only when chained with another bug     | Find chain partner, revalidate
NEEDS IMPROVEMENT  | Valid finding, report quality insufficient   | Fix flagged items, recheck gates
```

## Done when

- All 7 questions in the 7-Question Gate answered YES
- Always-Rejected List reviewed with zero matches
- Chain requirement resolved (standalone PASS or chain partner identified and documented)
- All 4 Pre-Submission Gates at PASS status
- CVSS 3.1 score calculated and validated against demonstrated impact
- Final verdict is SUBMIT with a complete pre-send checklist confirmed

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Gate 1 fails — PoC only works in your own session | Session-dependent state (CSRF token, account-specific condition) | Create a second test account and reproduce from scratch |
| Gate 2 fails — asset not confirmed in scope | Wildcard scope ambiguity or subdomain not listed | Email program contact or check scope changelog; when in doubt, do not submit |
| Gate 3 fails — impact statement is vague | Finding described technically but not in business terms | Answer: "Who loses what, and how many of them?" |
| Gate 4 fails — report contains real PII | PoC used production data instead of test accounts | Re-run PoC with test accounts, redact screenshots, replace request logs |
| Q4 fails — requires admin access | Found finding while logged in as admin test account | Verify whether the endpoint enforces authorization for lower-privilege roles |
| Q6 fails — impact is "technically possible" only | No concrete exploit demonstrated | Build a minimal working exploit that shows actual data access or action execution |
| CVSS score is Critical but program rates it High | Program applies internal severity mapping | Accept the program's rating; note your CVSS in the report for transparency |
| Stuck on chain requirement — no obvious partner | Finding is low-impact and no sibling bugs exist | Use bug-bounty-methodology skill to hunt for a chain partner; otherwise KILL |

## Notes

- Run this validation on every finding before drafting the full report — it saves hours of writing reports that will be rejected.
- CVSS is a starting point, not a contract. Programs apply internal modifiers; a CVSS 7.5 may pay as Medium if the program has a restricted severity map.
- The Always-Rejected List reflects patterns that consistently receive N/A responses across major platforms. These are not arbitrary — they represent findings that either have no real-world impact or are considered acceptable risk by most programs.
- A NEEDS CHAIN verdict is not a dead end. Many High and Critical findings are built from two Low findings. The chain-finding step is active research, not failure.
- Do not submit simultaneously to multiple programs if the asset is shared infrastructure. Confirm the owning program first.
- When a report comes back as Informational or Duplicate, re-run this gate on your next similar finding before submitting to identify the gap.
- Keep a personal rejected-findings log. Patterns in your own rejections (e.g., always failing Q6) reveal a specific skill gap to address in training.
