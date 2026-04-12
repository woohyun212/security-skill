---
name: isms-checklist
description: ISMS-P (Korean Information Security Management System) certification checklist and gap analysis
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
read -rp "Organization name: " ORG_NAME
echo ""
echo "Select the domain(s) to inspect:"
echo "  1) Management System Establishment and Operation (관리체계 수립 및 운영) - 16 controls"
echo "  2) Protection Measure Requirements (보호대책 요구사항) - 64 controls"
echo "  3) Personal Information Processing Stage Requirements (개인정보 처리 단계별 요구사항) - 22 controls"
echo "  all) All domains - 102 controls"
read -rp "Selection [1/2/3/all]: " DOMAIN_SEL
read -rp "Certification scope (optional): " SCOPE

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

```bash
python3 - "$REPORT_FILE" "$DOMAIN_SEL" <<'PYEOF'
import sys

report_file = sys.argv[1]
domain_sel = sys.argv[2]

# Domain 1: Management System Establishment and Operation (관리체계 수립 및 운영)
domain1 = {
    "id": "1",
    "name": "Management System Establishment and Operation (관리체계 수립 및 운영)",
    "categories": [
        {
            "id": "1.1",
            "name": "Establishing the Management System Foundation (관리체계 기반 마련)",
            "controls": [
                ("1.1.1", "Defining the scope of the information security and personal information protection management system (정보보호 및 개인정보보호 관리체계 범위 설정)"),
                ("1.1.2", "Designating the chief officer (최고책임자 지정)"),
                ("1.1.3", "Organizing the team structure (조직 구성)"),
                ("1.1.4", "Identifying assets within scope (범위 내 자산 식별)"),
                ("1.1.5", "Identifying and engaging stakeholders (이해관계자 식별 및 참여)"),
            ]
        },
        {
            "id": "1.2",
            "name": "Risk Management (위험 관리)",
            "controls": [
                ("1.2.1", "Identifying and classifying information assets (정보자산 식별 및 분류)"),
                ("1.2.2", "Analyzing current status and information flows (현황 및 흐름 분석)"),
                ("1.2.3", "Risk assessment (위험 평가)"),
                ("1.2.4", "Selecting protection measures (보호대책 선정)"),
            ]
        },
        {
            "id": "1.3",
            "name": "Operating the Management System (관리체계 운영)",
            "controls": [
                ("1.3.1", "Implementing protection measures (보호대책 구현)"),
                ("1.3.2", "Sharing protection measures (보호대책 공유)"),
                ("1.3.3", "Managing operational status (운영현황 관리)"),
            ]
        },
        {
            "id": "1.4",
            "name": "Reviewing and Improving the Management System (관리체계 점검 및 개선)",
            "controls": [
                ("1.4.1", "Reviewing compliance with legal requirements (법적 요구사항 준수 검토)"),
                ("1.4.2", "Reviewing the management system (관리체계 점검)"),
                ("1.4.3", "Improving the management system (관리체계 개선)"),
            ]
        },
    ]
}

# Domain 2: Protection Measure Requirements (보호대책 요구사항)
domain2 = {
    "id": "2",
    "name": "Protection Measure Requirements (보호대책 요구사항)",
    "categories": [
        {
            "id": "2.1",
            "name": "Policy, Organization, and Asset Management (정책, 조직, 자산 관리)",
            "controls": [
                ("2.1.1", "Maintaining policies (정책의 유지관리)"),
                ("2.1.2", "Maintaining the organization (조직의 유지관리)"),
                ("2.1.3", "Managing information assets (정보자산 관리)"),
            ]
        },
        {
            "id": "2.2",
            "name": "Personnel Security (인적 보안)",
            "controls": [
                ("2.2.1", "Designating and managing key role holders (주요 직무자 지정 및 관리)"),
                ("2.2.2", "Separation of duties (직무 분리)"),
                ("2.2.3", "Security pledges (보안 서약)"),
                ("2.2.4", "Awareness raising and training (인식제고 및 교육훈련)"),
                ("2.2.5", "Managing resignation and role changes (퇴직 및 직무변경 관리)"),
                ("2.2.6", "Responding to security violations (보안 위반 시 조치)"),
            ]
        },
        {
            "id": "2.3",
            "name": "Third-Party Security (외부자 보안)",
            "controls": [
                ("2.3.1", "Managing third-party inventory (외부자 현황 관리)"),
                ("2.3.2", "Security in third-party contracts (외부자 계약 시 보안)"),
                ("2.3.3", "Managing third-party security compliance (외부자 보안 이행 관리)"),
                ("2.3.4", "Security on contract changes and expiry (외부자 계약 변경 및 만료 시 보안)"),
            ]
        },
        {
            "id": "2.4",
            "name": "Physical Security (물리 보안)",
            "controls": [
                ("2.4.1", "Designating protected zones (보호구역 지정)"),
                ("2.4.2", "Access control (출입통제)"),
                ("2.4.3", "Protecting information systems (정보시스템 보호)"),
                ("2.4.4", "Operating protective facilities (보호설비 운영)"),
                ("2.4.5", "Work within protected zones (보호구역 내 작업)"),
                ("2.4.6", "Controlling devices brought in or out (반출입 기기 통제)"),
                ("2.4.7", "Work environment security (업무환경 보안)"),
            ]
        },
        {
            "id": "2.5",
            "name": "Authentication and Authorization Management (인증 및 권한 관리)",
            "controls": [
                ("2.5.1", "Managing user accounts (사용자 계정 관리)"),
                ("2.5.2", "User identification (사용자 식별)"),
                ("2.5.3", "User authentication (사용자 인증)"),
                ("2.5.4", "Password management (비밀번호 관리)"),
                ("2.5.5", "Managing privileged accounts and permissions (특수 계정 및 권한 관리)"),
                ("2.5.6", "Reviewing access rights (접근권한 검토)"),
            ]
        },
        {
            "id": "2.6",
            "name": "Access Control (접근통제)",
            "controls": [
                ("2.6.1", "Network access (네트워크 접근)"),
                ("2.6.2", "Information system access (정보시스템 접근)"),
                ("2.6.3", "Application access (응용프로그램 접근)"),
                ("2.6.4", "Database access (데이터베이스 접근)"),
                ("2.6.5", "Wireless network access (무선 네트워크 접근)"),
                ("2.6.6", "Remote access control (원격 접근 통제)"),
                ("2.6.7", "Internet access control (인터넷 접속 통제)"),
            ]
        },
        {
            "id": "2.7",
            "name": "Cryptography (암호화 적용)",
            "controls": [
                ("2.7.1", "Applying cryptographic policy (암호정책 적용)"),
                ("2.7.2", "Cryptographic key management (암호키 관리)"),
            ]
        },
        {
            "id": "2.8",
            "name": "Information System Acquisition and Development Security (정보시스템 도입 및 개발 보안)",
            "controls": [
                ("2.8.1", "Defining security requirements (보안 요구사항 정의)"),
                ("2.8.2", "Reviewing and testing security requirements (보안 요구사항 검토 및 시험)"),
                ("2.8.3", "Separating test and production environments (시험과 운영 환경 분리)"),
                ("2.8.4", "Test data security (시험 데이터 보안)"),
                ("2.8.5", "Managing source code (소스 프로그램 관리)"),
                ("2.8.6", "Releasing to production environment (운영환경 이관)"),
            ]
        },
        {
            "id": "2.9",
            "name": "System and Service Operations Management (시스템 및 서비스 운영 관리)",
            "controls": [
                ("2.9.1", "Change management (변경관리)"),
                ("2.9.2", "Performance and incident management (성능 및 장애관리)"),
                ("2.9.3", "Backup and recovery management (백업 및 복구 관리)"),
                ("2.9.4", "Log and access record management (로그 및 접속기록 관리)"),
                ("2.9.5", "Log and access record review (로그 및 접속기록 점검)"),
                ("2.9.6", "Time synchronization (시간 동기화)"),
                ("2.9.7", "Reuse and disposal of information assets (정보자산의 재사용 및 폐기)"),
            ]
        },
        {
            "id": "2.10",
            "name": "System and Service Security Management (시스템 및 서비스 보안 관리)",
            "controls": [
                ("2.10.1", "Operating security systems (보안시스템 운영)"),
                ("2.10.2", "Cloud security (클라우드 보안)"),
                ("2.10.3", "Public server security (공개서버 보안)"),
                ("2.10.4", "Electronic commerce and fintech security (전자거래 및 핀테크 보안)"),
                ("2.10.5", "Information transmission security (정보전송 보안)"),
                ("2.10.6", "Business endpoint security (업무용 단말기기 보안)"),
                ("2.10.7", "Removable storage media management (보조저장매체 관리)"),
                ("2.10.8", "Patch management (패치관리)"),
                ("2.10.9", "Malware control (악성코드 통제)"),
            ]
        },
        {
            "id": "2.11",
            "name": "Incident Prevention and Response (사고 예방 및 대응)",
            "controls": [
                ("2.11.1", "Establishing incident prevention and response framework (사고 예방 및 대응체계 구축)"),
                ("2.11.2", "Vulnerability inspection and remediation (취약점 점검 및 조치)"),
                ("2.11.3", "Anomaly analysis and monitoring (이상행위 분석 및 모니터링)"),
                ("2.11.4", "Incident response drills and improvement (사고 대응 훈련 및 개선)"),
                ("2.11.5", "Incident response and recovery (사고 대응 및 복구)"),
            ]
        },
        {
            "id": "2.12",
            "name": "Disaster Recovery (재해복구)",
            "controls": [
                ("2.12.1", "Safety measures for disasters and calamities (재해, 재난 대비 안전조치)"),
                ("2.12.2", "Disaster recovery testing and improvement (재해복구 시험 및 개선)"),
            ]
        },
    ]
}

# Domain 3: Personal Information Processing Stage Requirements (개인정보 처리 단계별 요구사항)
domain3 = {
    "id": "3",
    "name": "Personal Information Processing Stage Requirements (개인정보 처리 단계별 요구사항)",
    "categories": [
        {
            "id": "3.1",
            "name": "Protection Measures When Collecting Personal Information (개인정보 수집 시 보호조치)",
            "controls": [
                ("3.1.1", "Restricting personal information collection (개인정보 수집 제한)"),
                ("3.1.2", "Consent for collection of personal information (개인정보의 수집 동의)"),
                ("3.1.3", "Restricting processing of resident registration numbers (주민등록번호 처리 제한)"),
                ("3.1.4", "Restricting processing of sensitive and unique identification information (민감정보 및 고유식별정보의 처리 제한)"),
                ("3.1.5", "Protection measures for indirect collection (간접수집 보호조치)"),
                ("3.1.6", "Installation and operation of video surveillance devices (영상정보처리기기 설치·운영)"),
                ("3.1.7", "Measures for use in promotions and marketing (홍보 및 마케팅 목적 활용 시 조치)"),
            ]
        },
        {
            "id": "3.2",
            "name": "Protection Measures When Retaining and Using Personal Information (개인정보 보유 및 이용 시 보호조치)",
            "controls": [
                ("3.2.1", "Managing personal information inventory (개인정보 현황 관리)"),
                ("3.2.2", "Personal information quality management (개인정보 품질 관리)"),
                ("3.2.3", "Masking personal information and protection measures during use (개인정보 표시제한 및 이용 시 보호조치)"),
                ("3.2.4", "Protecting access to user devices (이용자 단말기 접근 보호)"),
                ("3.2.5", "Use and provision of personal information beyond original purpose (개인정보 목적 외 이용 및 제공)"),
            ]
        },
        {
            "id": "3.3",
            "name": "Protection Measures When Providing Personal Information (개인정보 제공 시 보호조치)",
            "controls": [
                ("3.3.1", "Providing personal information to third parties (개인정보 제3자 제공)"),
                ("3.3.2", "Outsourcing personal information processing tasks (개인정보 처리업무 위탁)"),
                ("3.3.3", "Transfer of personal information due to business succession (영업의 양수 등에 따른 개인정보 이전)"),
                ("3.3.4", "Cross-border transfer of personal information (개인정보의 국외 이전)"),
            ]
        },
        {
            "id": "3.4",
            "name": "Protection Measures When Destroying Personal Information (개인정보 파기 시 보호조치)",
            "controls": [
                ("3.4.1", "Destruction of personal information (개인정보의 파기)"),
                ("3.4.2", "Measures for retention after purpose has been fulfilled (처리목적 달성 후 보유 시 조치)"),
            ]
        },
        {
            "id": "3.5",
            "name": "Protecting Data Subject Rights (정보주체 권리보호)",
            "controls": [
                ("3.5.1", "Publishing the personal information processing policy (개인정보처리방침 공개)"),
                ("3.5.2", "Guaranteeing data subject rights (정보주체 권리보장)"),
                ("3.5.3", "Operating mobile video surveillance devices (이동형 영상정보처리기기 운영)"),
                ("3.5.4", "Processing pseudonymized information (가명정보 처리)"),
            ]
        },
    ]
}

# Determine domains to inspect
domains_to_check = []
if domain_sel in ('1', 'all'):
    domains_to_check.append(domain1)
if domain_sel in ('2', 'all'):
    domains_to_check.append(domain2)
if domain_sel in ('3', 'all'):
    domains_to_check.append(domain3)

if not domains_to_check:
    print("[!] Invalid domain selection. Please enter one of: 1, 2, 3, all")
    sys.exit(1)

all_results = {}
total_pass = total_fail = total_na = 0

for domain in domains_to_check:
    print(f"\n{'=' * 60}")
    print(f"Domain {domain['id']}: {domain['name']}")
    print("Answer each control with y(Compliant) / n(Non-compliant) / s(Not applicable)")
    print("=" * 60)

    for cat in domain['categories']:
        print(f"\n  [{cat['id']}] {cat['name']}")
        for ctrl_id, ctrl_name in cat['controls']:
            while True:
                ans = input(f"    {ctrl_id} {ctrl_name}\n    -> ").strip().lower()
                if ans in ('y', 'n', 's', ''):
                    break
                print("    Please enter one of: y, n, s")
            status = {'y': 'Compliant', 'n': 'Non-compliant', 's': 'N/A', '': 'N/A'}[ans]
            all_results[ctrl_id] = {'name': ctrl_name, 'status': status, 'domain': domain['name'], 'category': cat['name']}
            if status == 'Compliant':
                total_pass += 1
            elif status == 'Non-compliant':
                total_fail += 1
            else:
                total_na += 1

# Write report
with open(report_file, 'a') as f:
    f.write("## Inspection Results Summary\n\n")
    total = total_pass + total_fail + total_na
    compliance_rate = (total_pass / (total_pass + total_fail) * 100) if (total_pass + total_fail) > 0 else 0
    f.write(f"| Item | Count | Rate |\n")
    f.write(f"|------|-------|------|\n")
    f.write(f"| Compliant | {total_pass} | {compliance_rate:.1f}% |\n")
    f.write(f"| Non-compliant | {total_fail} | {100-compliance_rate:.1f}% |\n")
    f.write(f"| Not applicable | {total_na} | - |\n")
    f.write(f"| **Total** | **{total}** | |\n\n")

    f.write("## Control Item Status\n\n")
    f.write("| Control ID | Item | Domain | Status |\n")
    f.write("|------------|------|--------|--------|\n")
    for ctrl_id, data in all_results.items():
        status_icon = "✓" if data['status'] == 'Compliant' else ("✗" if data['status'] == 'Non-compliant' else "-")
        f.write(f"| {ctrl_id} | {data['name']} | {data['domain']} | {status_icon} {data['status']} |\n")

    f.write("\n## Gap Analysis and Remediation Recommendations\n\n")
    fail_items = [(k, v) for k, v in all_results.items() if v['status'] == 'Non-compliant']
    if fail_items:
        # Group by domain
        from collections import defaultdict
        by_domain = defaultdict(list)
        for ctrl_id, data in fail_items:
            by_domain[data['domain']].append((ctrl_id, data))

        for domain_name, items in by_domain.items():
            f.write(f"### {domain_name}\n\n")
            f.write(f"{len(items)} non-compliant item(s):\n\n")
            for ctrl_id, data in items:
                f.write(f"- **{ctrl_id}** {data['name']} ({data['category']})\n")
            f.write("\n")

        # Priority recommendations
        f.write("### Priority Remediation Recommendations\n\n")
        f.write("**Immediate action (HIGH)**: Non-compliant items related to personal information collection and processing, access control failures\n\n")
        f.write("**Short-term action (MEDIUM)**: Non-compliant items related to personnel security, physical security, and cryptography\n\n")
        f.write("**Mid-to-long-term planning (LOW)**: Management system documentation, training programs, disaster recovery planning\n\n")
    else:
        f.write("No non-compliant items — all applicable controls are compliant.\n\n")

    f.write(f"\n---\n\nReference: [KISA ISMS-P Certification](https://isms.kisa.or.kr)\n")

print(f"\n[+] Inspection complete!")
print(f"    Compliant: {total_pass} / Non-compliant: {total_fail} / Not applicable: {total_na}")
if (total_pass + total_fail) > 0:
    rate = total_pass / (total_pass + total_fail) * 100
    print(f"    Compliance rate: {rate:.1f}%")
PYEOF
```

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
