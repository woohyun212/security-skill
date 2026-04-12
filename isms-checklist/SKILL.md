---
name: isms-checklist
description: ISMS-P (Korean Information Security Management System) certification checklist and gap analysis
license: MIT
metadata:
  category: compliance
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

한국 정보보호 및 개인정보보호 관리체계(ISMS-P) 인증 기준에 따라 통제 항목을 점검합니다. 관리체계 수립 및 운영, 보호대책 요구사항, 개인정보 처리 단계별 요구사항 3개 도메인을 대화형으로 점검하고, 준수/미준수/해당없음 현황을 추적하여 우선순위별 개선 권고가 포함된 갭 분석 보고서를 생성합니다.

## 언제 사용하나요

- ISMS-P 최초 인증 신청 전 현황 파악이 필요할 때
- 인증 갱신 심사를 앞두고 내부 자가점검을 수행할 때
- 특정 통제 도메인의 준수 현황을 빠르게 파악할 때
- 정보보호 담당자가 관리체계 구축 로드맵을 수립할 때

## 사전 요구 사항

- 외부 도구 불필요 (체크리스트 기반)
- 점검 담당자의 조직 내 정보보호 정책/현황 지식
- (선택) KISA ISMS-P 인증 기준 문서 참고: https://isms.kisa.or.kr

## 입력

| 항목 | 설명 | 예시 |
|------|------|------|
| `ORG_NAME` | 점검 대상 기관/조직명 | `(주)테크컴퍼니` |
| `DOMAIN` | 점검 도메인 선택 (1/2/3/all) | `all` |
| `SCOPE` | 인증 범위 설명 (선택) | `전사 정보시스템 및 개인정보처리 서비스` |

## 워크플로

### 1단계: 점검 환경 설정

```bash
read -rp "기관/조직명: " ORG_NAME
echo ""
echo "점검할 도메인을 선택하세요:"
echo "  1) 관리체계 수립 및 운영 (16개 통제항목)"
echo "  2) 보호대책 요구사항 (64개 통제항목)"
echo "  3) 개인정보 처리 단계별 요구사항 (22개 통제항목)"
echo "  all) 전체 (102개 통제항목)"
read -rp "선택 [1/2/3/all]: " DOMAIN_SEL
read -rp "인증 범위 (선택): " SCOPE

REPORT_FILE="/tmp/isms_check_$(date +%Y%m%d_%H%M%S).md"
cat > "$REPORT_FILE" <<EOF
# ISMS-P 인증 기준 점검 결과

- **기관**: $ORG_NAME
- **인증 범위**: ${SCOPE:-미기재}
- **점검일**: $(date '+%Y-%m-%d')
- **도메인**: $DOMAIN_SEL

---
EOF
echo "[+] 보고서 초기화: $REPORT_FILE"
```

### 2단계: 관리체계 수립 및 운영 점검 (도메인 1)

```bash
python3 - "$REPORT_FILE" "$DOMAIN_SEL" <<'PYEOF'
import sys

report_file = sys.argv[1]
domain_sel = sys.argv[2]

# 도메인 1: 관리체계 수립 및 운영
domain1 = {
    "id": "1",
    "name": "관리체계 수립 및 운영",
    "categories": [
        {
            "id": "1.1",
            "name": "관리체계 기반 마련",
            "controls": [
                ("1.1.1", "정보보호 및 개인정보보호 관리체계 범위 설정"),
                ("1.1.2", "최고책임자 지정"),
                ("1.1.3", "조직 구성"),
                ("1.1.4", "범위 내 자산 식별"),
                ("1.1.5", "이해관계자 식별 및 참여"),
            ]
        },
        {
            "id": "1.2",
            "name": "위험 관리",
            "controls": [
                ("1.2.1", "정보자산 식별 및 분류"),
                ("1.2.2", "현황 및 흐름 분석"),
                ("1.2.3", "위험 평가"),
                ("1.2.4", "보호대책 선정"),
            ]
        },
        {
            "id": "1.3",
            "name": "관리체계 운영",
            "controls": [
                ("1.3.1", "보호대책 구현"),
                ("1.3.2", "보호대책 공유"),
                ("1.3.3", "운영현황 관리"),
            ]
        },
        {
            "id": "1.4",
            "name": "관리체계 점검 및 개선",
            "controls": [
                ("1.4.1", "법적 요구사항 준수 검토"),
                ("1.4.2", "관리체계 점검"),
                ("1.4.3", "관리체계 개선"),
            ]
        },
    ]
}

# 도메인 2: 보호대책 요구사항 (주요 항목)
domain2 = {
    "id": "2",
    "name": "보호대책 요구사항",
    "categories": [
        {
            "id": "2.1",
            "name": "정책, 조직, 자산 관리",
            "controls": [
                ("2.1.1", "정책의 유지관리"),
                ("2.1.2", "조직의 유지관리"),
                ("2.1.3", "정보자산 관리"),
            ]
        },
        {
            "id": "2.2",
            "name": "인적 보안",
            "controls": [
                ("2.2.1", "주요 직무자 지정 및 관리"),
                ("2.2.2", "직무 분리"),
                ("2.2.3", "보안 서약"),
                ("2.2.4", "인식제고 및 교육훈련"),
                ("2.2.5", "퇴직 및 직무변경 관리"),
                ("2.2.6", "보안 위반 시 조치"),
            ]
        },
        {
            "id": "2.3",
            "name": "외부자 보안",
            "controls": [
                ("2.3.1", "외부자 현황 관리"),
                ("2.3.2", "외부자 계약 시 보안"),
                ("2.3.3", "외부자 보안 이행 관리"),
                ("2.3.4", "외부자 계약 변경 및 만료 시 보안"),
            ]
        },
        {
            "id": "2.4",
            "name": "물리 보안",
            "controls": [
                ("2.4.1", "보호구역 지정"),
                ("2.4.2", "출입통제"),
                ("2.4.3", "정보시스템 보호"),
                ("2.4.4", "보호설비 운영"),
                ("2.4.5", "보호구역 내 작업"),
                ("2.4.6", "반출입 기기 통제"),
                ("2.4.7", "업무환경 보안"),
            ]
        },
        {
            "id": "2.5",
            "name": "인증 및 권한 관리",
            "controls": [
                ("2.5.1", "사용자 계정 관리"),
                ("2.5.2", "사용자 식별"),
                ("2.5.3", "사용자 인증"),
                ("2.5.4", "비밀번호 관리"),
                ("2.5.5", "특수 계정 및 권한 관리"),
                ("2.5.6", "접근권한 검토"),
            ]
        },
        {
            "id": "2.6",
            "name": "접근통제",
            "controls": [
                ("2.6.1", "네트워크 접근"),
                ("2.6.2", "정보시스템 접근"),
                ("2.6.3", "응용프로그램 접근"),
                ("2.6.4", "데이터베이스 접근"),
                ("2.6.5", "무선 네트워크 접근"),
                ("2.6.6", "원격 접근 통제"),
                ("2.6.7", "인터넷 접속 통제"),
            ]
        },
        {
            "id": "2.7",
            "name": "암호화 적용",
            "controls": [
                ("2.7.1", "암호정책 적용"),
                ("2.7.2", "암호키 관리"),
            ]
        },
        {
            "id": "2.8",
            "name": "정보시스템 도입 및 개발 보안",
            "controls": [
                ("2.8.1", "보안 요구사항 정의"),
                ("2.8.2", "보안 요구사항 검토 및 시험"),
                ("2.8.3", "시험과 운영 환경 분리"),
                ("2.8.4", "시험 데이터 보안"),
                ("2.8.5", "소스 프로그램 관리"),
                ("2.8.6", "운영환경 이관"),
            ]
        },
        {
            "id": "2.9",
            "name": "시스템 및 서비스 운영 관리",
            "controls": [
                ("2.9.1", "변경관리"),
                ("2.9.2", "성능 및 장애관리"),
                ("2.9.3", "백업 및 복구 관리"),
                ("2.9.4", "로그 및 접속기록 관리"),
                ("2.9.5", "로그 및 접속기록 점검"),
                ("2.9.6", "시간 동기화"),
                ("2.9.7", "정보자산의 재사용 및 폐기"),
            ]
        },
        {
            "id": "2.10",
            "name": "시스템 및 서비스 보안 관리",
            "controls": [
                ("2.10.1", "보안시스템 운영"),
                ("2.10.2", "클라우드 보안"),
                ("2.10.3", "공개서버 보안"),
                ("2.10.4", "전자거래 및 핀테크 보안"),
                ("2.10.5", "정보전송 보안"),
                ("2.10.6", "업무용 단말기기 보안"),
                ("2.10.7", "보조저장매체 관리"),
                ("2.10.8", "패치관리"),
                ("2.10.9", "악성코드 통제"),
            ]
        },
        {
            "id": "2.11",
            "name": "사고 예방 및 대응",
            "controls": [
                ("2.11.1", "사고 예방 및 대응체계 구축"),
                ("2.11.2", "취약점 점검 및 조치"),
                ("2.11.3", "이상행위 분석 및 모니터링"),
                ("2.11.4", "사고 대응 훈련 및 개선"),
                ("2.11.5", "사고 대응 및 복구"),
            ]
        },
        {
            "id": "2.12",
            "name": "재해복구",
            "controls": [
                ("2.12.1", "재해, 재난 대비 안전조치"),
                ("2.12.2", "재해복구 시험 및 개선"),
            ]
        },
    ]
}

# 도메인 3: 개인정보 처리 단계별 요구사항
domain3 = {
    "id": "3",
    "name": "개인정보 처리 단계별 요구사항",
    "categories": [
        {
            "id": "3.1",
            "name": "개인정보 수집 시 보호조치",
            "controls": [
                ("3.1.1", "개인정보 수집 제한"),
                ("3.1.2", "개인정보의 수집 동의"),
                ("3.1.3", "주민등록번호 처리 제한"),
                ("3.1.4", "민감정보 및 고유식별정보의 처리 제한"),
                ("3.1.5", "간접수집 보호조치"),
                ("3.1.6", "영상정보처리기기 설치·운영"),
                ("3.1.7", "홍보 및 마케팅 목적 활용 시 조치"),
            ]
        },
        {
            "id": "3.2",
            "name": "개인정보 보유 및 이용 시 보호조치",
            "controls": [
                ("3.2.1", "개인정보 현황 관리"),
                ("3.2.2", "개인정보 품질 관리"),
                ("3.2.3", "개인정보 표시제한 및 이용 시 보호조치"),
                ("3.2.4", "이용자 단말기 접근 보호"),
                ("3.2.5", "개인정보 목적 외 이용 및 제공"),
            ]
        },
        {
            "id": "3.3",
            "name": "개인정보 제공 시 보호조치",
            "controls": [
                ("3.3.1", "개인정보 제3자 제공"),
                ("3.3.2", "개인정보 처리업무 위탁"),
                ("3.3.3", "영업의 양수 등에 따른 개인정보 이전"),
                ("3.3.4", "개인정보의 국외 이전"),
            ]
        },
        {
            "id": "3.4",
            "name": "개인정보 파기 시 보호조치",
            "controls": [
                ("3.4.1", "개인정보의 파기"),
                ("3.4.2", "처리목적 달성 후 보유 시 조치"),
            ]
        },
        {
            "id": "3.5",
            "name": "정보주체 권리보호",
            "controls": [
                ("3.5.1", "개인정보처리방침 공개"),
                ("3.5.2", "정보주체 권리보장"),
                ("3.5.3", "이동형 영상정보처리기기 운영"),
                ("3.5.4", "가명정보 처리"),
            ]
        },
    ]
}

# 점검 대상 도메인 결정
domains_to_check = []
if domain_sel in ('1', 'all'):
    domains_to_check.append(domain1)
if domain_sel in ('2', 'all'):
    domains_to_check.append(domain2)
if domain_sel in ('3', 'all'):
    domains_to_check.append(domain3)

if not domains_to_check:
    print("[!] 잘못된 도메인 선택. 1, 2, 3, all 중 하나를 입력하세요.")
    sys.exit(1)

all_results = {}
total_pass = total_fail = total_na = 0

for domain in domains_to_check:
    print(f"\n{'=' * 60}")
    print(f"도메인 {domain['id']}: {domain['name']}")
    print("각 통제항목에 y(준수)/n(미준수)/s(해당없음) 으로 답하세요")
    print("=" * 60)

    for cat in domain['categories']:
        print(f"\n  [{cat['id']}] {cat['name']}")
        for ctrl_id, ctrl_name in cat['controls']:
            while True:
                ans = input(f"    {ctrl_id} {ctrl_name}\n    -> ").strip().lower()
                if ans in ('y', 'n', 's', ''):
                    break
                print("    y, n, s 중 하나를 입력하세요")
            status = {'y': '준수', 'n': '미준수', 's': '해당없음', '': '해당없음'}[ans]
            all_results[ctrl_id] = {'name': ctrl_name, 'status': status, 'domain': domain['name'], 'category': cat['name']}
            if status == '준수':
                total_pass += 1
            elif status == '미준수':
                total_fail += 1
            else:
                total_na += 1

# 보고서 작성
with open(report_file, 'a') as f:
    f.write("## 점검 결과 요약\n\n")
    total = total_pass + total_fail + total_na
    compliance_rate = (total_pass / (total_pass + total_fail) * 100) if (total_pass + total_fail) > 0 else 0
    f.write(f"| 항목 | 건수 | 비율 |\n")
    f.write(f"|------|------|------|\n")
    f.write(f"| 준수 | {total_pass} | {compliance_rate:.1f}% |\n")
    f.write(f"| 미준수 | {total_fail} | {100-compliance_rate:.1f}% |\n")
    f.write(f"| 해당없음 | {total_na} | - |\n")
    f.write(f"| **합계** | **{total}** | |\n\n")

    f.write("## 통제항목별 현황\n\n")
    f.write("| 통제항목 ID | 항목명 | 도메인 | 상태 |\n")
    f.write("|------------|--------|--------|------|\n")
    for ctrl_id, data in all_results.items():
        status_icon = "✓" if data['status'] == '준수' else ("✗" if data['status'] == '미준수' else "-")
        f.write(f"| {ctrl_id} | {data['name']} | {data['domain']} | {status_icon} {data['status']} |\n")

    f.write("\n## 갭 분석 및 개선 권고\n\n")
    fail_items = [(k, v) for k, v in all_results.items() if v['status'] == '미준수']
    if fail_items:
        # 도메인별 그룹화
        from collections import defaultdict
        by_domain = defaultdict(list)
        for ctrl_id, data in fail_items:
            by_domain[data['domain']].append((ctrl_id, data))

        for domain_name, items in by_domain.items():
            f.write(f"### {domain_name}\n\n")
            f.write(f"미준수 항목 {len(items)}건:\n\n")
            for ctrl_id, data in items:
                f.write(f"- **{ctrl_id}** {data['name']} ({data['category']})\n")
            f.write("\n")

        # 우선순위 권고
        f.write("### 우선순위 개선 권고\n\n")
        f.write("**즉시 조치 (HIGH)**: 개인정보 수집·처리 관련 미준수 항목, 접근통제 미준수\n\n")
        f.write("**단기 조치 (MEDIUM)**: 인적 보안, 물리 보안, 암호화 관련 미준수 항목\n\n")
        f.write("**중장기 계획 (LOW)**: 관리체계 문서화, 교육 훈련, 재해복구 계획 수립\n\n")
    else:
        f.write("미준수 항목 없음 — 모든 해당 통제항목 준수\n\n")

    f.write(f"\n---\n\n참고: [KISA ISMS-P 인증](https://isms.kisa.or.kr)\n")

print(f"\n[+] 점검 완료!")
print(f"    준수: {total_pass}건 / 미준수: {total_fail}건 / 해당없음: {total_na}건")
if (total_pass + total_fail) > 0:
    rate = total_pass / (total_pass + total_fail) * 100
    print(f"    준수율: {rate:.1f}%")
PYEOF
```

### 3단계: 갭 분석 보고서 출력

```bash
echo ""
echo "=== 갭 분석 보고서 ==="
grep -A 50 "## 갭 분석" "$REPORT_FILE" | head -50

echo ""
echo "=== ISMS-P 인증 준비 체크리스트 ==="
echo ""
echo "[인증 신청 전 필수 확인 사항]"
echo "  1. 위험평가 결과서 및 위험 수용 기준 문서화 완료"
echo "  2. 내부 심사원 양성 또는 외부 컨설팅 확보"
echo "  3. 최고책임자(CISO/CPO) 지정 및 조직 구성 완료"
echo "  4. 개인정보 처리방침 최신화 및 공개"
echo "  5. 사고 대응 절차서 및 훈련 기록 유지"
echo ""
echo "[참조 자료]"
echo "  - KISA ISMS-P 인증 안내: https://isms.kisa.or.kr"
echo "  - 인증 기준 해설서: https://isms.kisa.or.kr/main/ispims/guide/"
echo "  - 개인정보 보호법: https://www.law.go.kr/법령/개인정보보호법"
echo ""
echo "[+] 상세 보고서: $REPORT_FILE"
```

## 완료 조건

- 선택한 도메인의 모든 통제항목 점검 완료
- `/tmp/isms_check_<날짜>.md` 보고서에 준수/미준수/해당없음 현황 저장됨
- 준수율 계산 및 우선순위별 개선 권고 포함
- 미준수 항목별 개선 방향 제시됨

## 실패 모드

| 문제 | 원인 | 해결책 |
|------|------|--------|
| 점검 중단 | 세션 종료 또는 오류 | 재실행 후 진행된 항목은 s(해당없음)로 스킵 |
| 보고서 파일 생성 실패 | 디스크 권한 문제 | `REPORT_FILE=~/isms_result.md` 로 변경 |
| 항목 이해 어려움 | 기준 해석 불명확 | KISA 인증 기준 해설서 및 FAQ 참고 |
| 도메인 선택 오류 | 잘못된 입력 | 1, 2, 3, all 중 하나 재입력 |

## 참고 사항

- 본 스킬은 자가점검 도구로, 공식 ISMS-P 인증 심사를 대체하지 않습니다.
- 인증 취득을 위해서는 KISA 지정 인증기관(ISMS-P 심사기관)을 통한 공식 심사가 필요합니다.
- 개인정보 처리 도메인(3)은 개인정보보호법 적용 대상 조직에만 해당합니다. 개인정보를 처리하지 않는 경우 ISMS(정보보호 관리체계) 인증을 검토하세요.
- 준수율 목표치: 인증 신청 권장 준수율 80% 이상 (필수 항목 100%)
- 웹 기반 OWASP 점검이 필요하다면 `owasp-check` 스킬과 병행 사용을 권장합니다.
