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
APP_NAME="${SECSKILL_APP_NAME:-}"
if [ -z "$APP_NAME" ]; then
  read -rp "Application name: " APP_NAME
fi
APP_TYPE="${SECSKILL_APP_TYPE:-}"
if [ -z "$APP_TYPE" ]; then
  read -rp "Type (web/api/mobile): " APP_TYPE
fi
TECH_STACK="${SECSKILL_TECH_STACK:-}"
if [ -z "$TECH_STACK" ]; then
  read -rp "Tech stack (e.g. Node.js, PostgreSQL): " TECH_STACK
fi

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

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full OWASP Top 10 2021 checklist (10 categories, 35 questions, reference URLs, and remediation priority guide).

The script iterates all 10 categories (A01–A10), prompts `y`/`n`/`s` for each question, then writes a compliance matrix and remediation list to the report file.

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

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full remediation priority guide (HIGH/MEDIUM/LOW bands with category groupings).

```bash
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
