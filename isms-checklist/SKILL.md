---
name: isms-checklist
description: Interactive gap analysis against Korea's ISMS-P 102-control certification framework (management, protection, personal information)
license: MIT
metadata:
  category: compliance
  locale: en
  phase: v1
---

## What this skill does

Inspects control items against the ISMS-P (Information Security and Personal Information Protection Management System, 정보보호 및 개인정보보호 관리체계) certification criteria. Interactively reviews three domains — Management System Establishment and Operation (관리체계 수립 및 운영), Protection Measure Requirements (보호대책 요구사항), and Personal Information Processing Stage Requirements (개인정보 처리 단계별 요구사항) — tracks compliant/non-compliant/not-applicable status, and generates a gap analysis report with prioritized remediation recommendations.

## When to use

- When assessing current status before applying for initial ISMS-P certification
- When conducting an internal self-assessment ahead of a certification renewal audit
- When quickly gauging compliance status for a specific control domain
- When information security personnel are building a management system roadmap

## Prerequisites

- No external tools required (checklist-based)
- Inspector's knowledge of the organization's information security policies and current state
- (Optional) KISA ISMS-P certification criteria document: https://isms.kisa.or.kr

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `ORG_NAME` | Name of the organization under review | `TechCompany Inc.` |
| `DOMAIN` | Domain selection (1/2/3/all) | `all` |
| `SCOPE` | Certification scope description (optional) | `All enterprise information systems and personal data processing services` |

## Workflow

### Step 1: Configure the inspection environment

```bash
ORG_NAME="${SECSKILL_ORG_NAME:-}"
if [ -z "$ORG_NAME" ]; then
  read -rp "Organization name: " ORG_NAME
fi
echo ""
echo "Select the domain(s) to inspect:"
echo "  1) Management System Establishment and Operation (관리체계 수립 및 운영) - 16 controls"
echo "  2) Protection Measure Requirements (보호대책 요구사항) - 64 controls"
echo "  3) Personal Information Processing Stage Requirements (개인정보 처리 단계별 요구사항) - 22 controls"
echo "  all) All domains - 102 controls"
DOMAIN_SEL="${SECSKILL_DOMAIN_SEL:-}"
if [ -z "$DOMAIN_SEL" ]; then
  read -rp "Selection [1/2/3/all]: " DOMAIN_SEL
fi
SCOPE="${SECSKILL_SCOPE:-}"
if [ -z "$SCOPE" ]; then
  read -rp "Certification scope (optional): " SCOPE
fi

REPORT_FILE="/tmp/isms_check_$(date +%Y%m%d_%H%M%S).md"
cat > "$REPORT_FILE" <<EOF
# ISMS-P Certification Criteria Inspection Results

- **Organization**: $ORG_NAME
- **Certification scope**: ${SCOPE:-Not specified}
- **Inspection date**: $(date '+%Y-%m-%d')
- **Domain**: $DOMAIN_SEL

---
EOF
echo "[+] Report initialized: $REPORT_FILE"
```

### Step 2: Run domain inspection

For each selected domain, the inspector answers each control item with:
- `y` — Compliant
- `n` — Non-compliant
- `s` — Not applicable

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the complete 102-item ISMS-P control catalog organized by domain (management system, protection measures, personal information processing).

The session iterates through each domain's categories and controls in order, collecting responses interactively. Results are accumulated in memory and written to the report file upon completion.

**Answer each control at the prompt:**

```
==============================
Domain 1: Management System Establishment and Operation (관리체계 수립 및 운영)
Answer each control with y(Compliant) / n(Non-compliant) / s(Not applicable)
==============================

  [1.1] Establishing the Management System Foundation
    1.1.1 Defining the scope ...
    -> y
    1.1.2 Designating the chief officer ...
    -> n
    ...
```

After all controls are answered, the script writes the summary, per-control status table, and gap analysis to `$REPORT_FILE`.

> **Reference**: See [REFERENCE.md](REFERENCE.md) for report generation logic including summary table structure, compliance rate formula, and priority remediation tier definitions.

### Step 3: Print gap analysis report

```bash
echo ""
echo "=== Gap Analysis Report ==="
grep -A 50 "## Gap Analysis" "$REPORT_FILE" | head -50

echo ""
echo "=== ISMS-P Certification Preparation Checklist ==="
echo ""
echo "[Required items to confirm before applying for certification]"
echo "  1. Risk assessment results and risk acceptance criteria documented"
echo "  2. Internal auditors trained or external consulting secured"
echo "  3. Chief officer (CISO/CPO) designated and organization structured"
echo "  4. Personal information processing policy updated and published"
echo "  5. Incident response procedures and training records maintained"
echo ""
echo "[Reference materials]"
echo "  - KISA ISMS-P Certification guide: https://isms.kisa.or.kr"
echo "  - Certification criteria commentary: https://isms.kisa.or.kr/main/ispims/guide/"
echo "  - Personal Information Protection Act: https://www.law.go.kr/법령/개인정보보호법"
echo ""
echo "[+] Detailed report: $REPORT_FILE"
```

## Done when

- All control items in the selected domain(s) have been inspected
- Compliant/Non-compliant/Not-applicable status saved to `/tmp/isms_check_<date>.md` report
- Compliance rate calculated and prioritized remediation recommendations included
- Remediation direction provided for each non-compliant item

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Inspection interrupted | Session closed or error | Re-run and skip completed items with s (not applicable) |
| Report file creation failed | Disk permission issue | Change to `REPORT_FILE=~/isms_result.md` |
| Item hard to understand | Ambiguous criteria interpretation | Refer to KISA certification criteria commentary and FAQ |
| Invalid domain selection | Wrong input | Re-enter one of: 1, 2, 3, all |

## Notes

- This skill is a self-assessment tool and does not replace an official ISMS-P certification audit.
- To obtain certification, an official audit through a KISA-designated certification body (ISMS-P auditor) is required.
- Domain 3 (Personal Information Processing) applies only to organizations subject to the Personal Information Protection Act. Organizations that do not process personal information should consider ISMS (Information Security Management System) certification instead.
- Recommended compliance rate target: 80% or higher to apply for certification (100% for mandatory items).
- If web-based OWASP inspection is also needed, recommend running alongside the `owasp-check` skill.
