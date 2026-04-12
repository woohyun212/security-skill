---
name: owasp-check
description: OWASP Top 10 (2021) checklist-based inspection and compliance matrix generation
license: MIT
metadata:
  category: compliance
  locale: en
  phase: v1
---

## What this skill does

Inspects security controls of a target application against the OWASP Top 10 2021 standard. Queries the defense status for each of the 10 categories (A01–A10) and generates a Pass/Fail/N-A compliance matrix. Provides prioritized remediation recommendations with official OWASP reference links for each failed item.

## When to use

- When conducting an application security review or pre-release inspection
- When performing an OWASP-based self-assessment in preparation for a security audit
- When systematically communicating security requirements to a development team
- When identifying risk priorities before a penetration test

## Prerequisites

- No external tools required (checklist-based)
- Inspector's knowledge of the target application's technology stack

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `APP_NAME` | Name of the application under review | `MyWebApp v2.3` |
| `APP_TYPE` | Application type | `web` / `api` / `mobile` |
| `TECH_STACK` | Technology stack in use (optional) | `Node.js, PostgreSQL, React` |

## Workflow

### Step 1: Collect target application information

```bash
read -rp "Application name: " APP_NAME
read -rp "Type (web/api/mobile): " APP_TYPE
read -rp "Tech stack (e.g. Node.js, PostgreSQL): " TECH_STACK

REPORT_FILE="/tmp/owasp_check_$(date +%Y%m%d_%H%M%S).md"
echo "# OWASP Top 10 2021 Inspection Results" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- **Target**: $APP_NAME" >> "$REPORT_FILE"
echo "- **Type**: $APP_TYPE" >> "$REPORT_FILE"
echo "- **Stack**: $TECH_STACK" >> "$REPORT_FILE"
echo "- **Date**: $(date '+%Y-%m-%d')" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "[+] Report file initialized: $REPORT_FILE"
```

### Step 2: Query each OWASP Top 10 2021 category

```bash
python3 - "$REPORT_FILE" "$APP_NAME" <<'PYEOF'
import sys

report_file = sys.argv[1]
app_name = sys.argv[2]

categories = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "questions": [
            "Is vertical/horizontal privilege separation implemented? (e.g. regular users cannot access admin pages)",
            "Is bypass of authorization via direct URL access or parameter tampering blocked?",
            "Does the CORS policy explicitly restrict allowed origins?",
            "Is directory listing disabled?",
        ],
        "ref": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "questions": [
            "Is TLS 1.2 or higher applied to data in transit?",
            "Are passwords stored using one-way hashes such as bcrypt/Argon2/scrypt?",
            "Is sensitive data (card numbers, SSNs, etc.) encrypted at rest?",
            "Are there no hardcoded encryption keys or credentials?",
        ],
        "ref": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
    },
    {
        "id": "A03",
        "name": "Injection",
        "questions": [
            "Are parameterized queries (Prepared Statements) used for all DB queries?",
            "Is server-side input validation implemented for user input?",
            "Is raw query usage minimized when using an ORM?",
            "Is user input excluded from OS command execution?",
        ],
        "ref": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "questions": [
            "Is threat modeling performed during the design phase?",
            "Are security requirements defined for business logic?",
            "Is rate limiting implemented for critical functions?",
        ],
        "ref": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "questions": [
            "Are unnecessary features, ports, services, and accounts disabled?",
            "Have default accounts/passwords been changed?",
            "Do error messages avoid exposing stack traces or internal information?",
            "Are security HTTP headers (CSP, HSTS, X-Frame-Options, etc.) configured?",
        ],
        "ref": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "questions": [
            "Are the versions of libraries/frameworks in use regularly reviewed?",
            "Is there a process to promptly patch components with known CVEs?",
            "Is an SCA (Software Composition Analysis) tool integrated into CI/CD?",
        ],
        "ref": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "questions": [
            "Is account lockout or CAPTCHA implemented to defend against brute-force attacks?",
            "Is multi-factor authentication (MFA) supported (especially for admin accounts)?",
            "Is the session ID regenerated after login?",
            "Are password complexity requirements enforced?",
        ],
        "ref": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    },
    {
        "id": "A08",
        "name": "Software and Data Integrity Failures",
        "questions": [
            "Does the CI/CD pipeline include integrity verification?",
            "Are integrity hashes (SRI) verified for external CDN/packages?",
            "Are untrusted data sources blocked during deserialization?",
        ],
        "ref": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "questions": [
            "Are login failures, authorization errors, and input validation failures logged?",
            "Do logs avoid including sensitive information (passwords, tokens)?",
            "Is there an alerting/monitoring system for security events?",
            "Are logs stored in a tamper-resistant remote repository?",
        ],
        "ref": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "questions": [
            "Is an allowlist used for server-side requests to user-supplied URLs?",
            "Are requests to internal network addresses (169.254.x.x, 10.x.x.x, etc.) blocked?",
            "Is URL redirect following disabled?",
        ],
        "ref": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
    },
]

results = {}

print("\n" + "=" * 60)
print("OWASP Top 10 2021 Category Inspection")
print("Answer each question with y(Pass) / n(Fail) / s(Skip/N-A)")
print("=" * 60)

for cat in categories:
    print(f"\n[{cat['id']}] {cat['name']}")
    cat_results = []
    for i, q in enumerate(cat['questions'], 1):
        while True:
            ans = input(f"  Q{i}. {q}\n  -> ").strip().lower()
            if ans in ('y', 'n', 's', ''):
                break
            print("  Please enter one of: y, n, s")
        status = {'y': 'PASS', 'n': 'FAIL', 's': 'N/A', '': 'N/A'}[ans]
        cat_results.append((q, status))
    results[cat['id']] = {'name': cat['name'], 'items': cat_results, 'ref': cat['ref']}

# Generate compliance matrix
with open(report_file, 'a') as f:
    f.write("## Compliance Matrix\n\n")
    f.write("| ID | Category | PASS | FAIL | N/A | Result |\n")
    f.write("|-----|---------|:----:|:----:|:---:|--------|\n")

    fail_items = []
    for cat_id, data in results.items():
        passes = sum(1 for _, s in data['items'] if s == 'PASS')
        fails = sum(1 for _, s in data['items'] if s == 'FAIL')
        na = sum(1 for _, s in data['items'] if s == 'N/A')
        total = passes + fails
        if total == 0:
            overall = "N/A"
        elif fails == 0:
            overall = "PASS"
        else:
            overall = f"FAIL ({fails})"
            fail_items.append((cat_id, data))
        f.write(f"| {cat_id} | {data['name']} | {passes} | {fails} | {na} | {overall} |\n")

    f.write("\n## Remediation Recommendations for Failed Items\n\n")
    if fail_items:
        for cat_id, data in fail_items:
            f.write(f"### {cat_id}: {data['name']}\n\n")
            f.write(f"**Reference**: {data['ref']}\n\n")
            for q, s in data['items']:
                if s == 'FAIL':
                    f.write(f"- [ ] {q}\n")
            f.write("\n")
    else:
        f.write("No failed items.\n\n")

print("\n[+] Inspection complete!")
PYEOF
```

### Step 3: Print compliance matrix

```bash
echo ""
echo "=== Final Compliance Matrix ==="
grep -A 20 "## Compliance Matrix" "$REPORT_FILE" | head -20

FAIL_COUNT=$(grep -c "FAIL" "$REPORT_FILE" 2>/dev/null || echo 0)
echo ""
echo "[Summary]"
echo "  Total failed items: $FAIL_COUNT"
echo "  Detailed report: $REPORT_FILE"
```

### Step 4: Print prioritized remediation recommendations

```bash
echo ""
echo "=== Prioritized Remediation Recommendations ==="
echo ""
echo "[HIGH] Immediate action required"
echo "  A01 Broken Access Control, A03 Injection, A07 Authentication Failures -> Direct data exposure risk"
echo ""
echo "[MEDIUM] Short-term action"
echo "  A02 Cryptographic Failures, A05 Security Misconfiguration, A06 Outdated Components -> Resolved by patching/reconfiguration"
echo ""
echo "[LOW] Long-term planning"
echo "  A04 Insecure Design, A08 Integrity Failures, A09 Logging Failures, A10 SSRF -> Process/architecture improvements"
echo ""
echo "[+] Full OWASP Top 10 reference: https://owasp.org/Top10/"
```

## Done when

- All 10 categories have been queried
- Compliance matrix saved to `/tmp/owasp_check_<date>.md` report
- OWASP reference links and remediation checklists included for each FAIL item

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Inspection interrupted | Terminal session closed | Re-run and skip completed items with N/A (s) |
| Report file missing | `/tmp` permission issue | Change to `REPORT_FILE=~/owasp_result.md` |
| Question hard to understand | Insufficient technical context | Refer to the description section of each reference link |

## Notes

- Use N/A (s) when a question does not apply to the current stack (e.g. server-side rendering questions for an SPA app).
- Share inspection results with the security team or development team to build a remediation roadmap.
- If preparing for ISMS-P certification, recommend running this skill alongside the `isms-checklist` skill.
- Inspection results do not replace a formal audit; use alongside professional penetration testing.
