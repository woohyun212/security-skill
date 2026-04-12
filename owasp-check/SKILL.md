---
name: owasp-check
description: OWASP Top 10 (2021) checklist-based inspection and compliance matrix generation
license: MIT
metadata:
  category: compliance
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

OWASP Top 10 2021 기준으로 대상 애플리케이션의 보안 통제를 점검합니다. 10개 카테고리(A01~A10)별로 방어 현황을 질의하고, Pass/Fail/N-A 컴플라이언스 매트릭스를 생성합니다. 실패 항목에 대해 공식 OWASP 참조 링크와 함께 우선순위별 개선 방안을 제공합니다.

## 언제 사용하나요

- 애플리케이션 보안 리뷰 또는 출시 전 점검을 수행할 때
- 보안 감사 준비를 위한 OWASP 기반 자가진단이 필요할 때
- 개발팀에게 보안 요구사항을 체계적으로 전달할 때
- 침투 테스트 전 위험 우선순위를 파악할 때

## 사전 요구 사항

- 외부 도구 불필요 (체크리스트 기반)
- 점검 담당자의 대상 애플리케이션 기술 스택 지식

## 입력

| 항목 | 설명 | 예시 |
|------|------|------|
| `APP_NAME` | 점검 대상 애플리케이션 이름 | `MyWebApp v2.3` |
| `APP_TYPE` | 애플리케이션 유형 | `web` / `api` / `mobile` |
| `TECH_STACK` | 사용 기술 스택 (선택) | `Node.js, PostgreSQL, React` |

## 워크플로

### 1단계: 점검 대상 정보 수집

```bash
read -rp "애플리케이션 이름: " APP_NAME
read -rp "유형 (web/api/mobile): " APP_TYPE
read -rp "기술 스택 (예: Node.js, PostgreSQL): " TECH_STACK

REPORT_FILE="/tmp/owasp_check_$(date +%Y%m%d_%H%M%S).md"
echo "# OWASP Top 10 2021 점검 결과" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- **대상**: $APP_NAME" >> "$REPORT_FILE"
echo "- **유형**: $APP_TYPE" >> "$REPORT_FILE"
echo "- **스택**: $TECH_STACK" >> "$REPORT_FILE"
echo "- **점검일**: $(date '+%Y-%m-%d')" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "[+] 보고서 파일 초기화: $REPORT_FILE"
```

### 2단계: OWASP Top 10 2021 항목별 질의

```bash
python3 - "$REPORT_FILE" "$APP_NAME" <<'PYEOF'
import sys

report_file = sys.argv[1]
app_name = sys.argv[2]

categories = [
    {
        "id": "A01",
        "name": "접근 통제 취약점 (Broken Access Control)",
        "questions": [
            "수직/수평 권한 분리가 구현되어 있습니까? (예: 일반 사용자가 관리자 페이지 접근 불가)",
            "URL 직접 접근, 파라미터 변조를 통한 권한 우회가 차단되어 있습니까?",
            "CORS 정책이 허용 오리진을 명시적으로 제한합니까?",
            "디렉토리 리스팅이 비활성화되어 있습니까?",
        ],
        "ref": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    },
    {
        "id": "A02",
        "name": "암호화 실패 (Cryptographic Failures)",
        "questions": [
            "전송 중 데이터에 TLS 1.2 이상이 적용되어 있습니까?",
            "비밀번호가 bcrypt/Argon2/scrypt 등 단방향 해시로 저장됩니까?",
            "민감 데이터(카드번호, SSN 등)가 암호화되어 저장됩니까?",
            "하드코딩된 암호화 키나 자격증명이 없습니까?",
        ],
        "ref": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
    },
    {
        "id": "A03",
        "name": "인젝션 (Injection)",
        "questions": [
            "모든 DB 쿼리에 파라미터화 쿼리(Prepared Statement)를 사용합니까?",
            "사용자 입력에 대한 서버 측 입력 검증이 구현되어 있습니까?",
            "ORM 사용 시 raw 쿼리 사용을 최소화하고 있습니까?",
            "OS 명령어 실행 시 사용자 입력이 포함되지 않도록 통제합니까?",
        ],
        "ref": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    {
        "id": "A04",
        "name": "안전하지 않은 설계 (Insecure Design)",
        "questions": [
            "위협 모델링(Threat Modeling)이 설계 단계에서 수행됩니까?",
            "비즈니스 로직에 대한 보안 요구사항이 정의되어 있습니까?",
            "중요 기능에 대한 속도 제한(Rate Limiting)이 구현되어 있습니까?",
        ],
        "ref": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
    },
    {
        "id": "A05",
        "name": "보안 설정 오류 (Security Misconfiguration)",
        "questions": [
            "불필요한 기능, 포트, 서비스, 계정이 비활성화되어 있습니까?",
            "기본 계정/비밀번호가 변경되었습니까?",
            "오류 메시지에 스택 트레이스나 내부 정보가 노출되지 않습니까?",
            "보안 HTTP 헤더(CSP, HSTS, X-Frame-Options 등)가 설정되어 있습니까?",
        ],
        "ref": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    {
        "id": "A06",
        "name": "취약하고 오래된 컴포넌트 (Vulnerable and Outdated Components)",
        "questions": [
            "사용 중인 라이브러리/프레임워크 버전을 정기적으로 확인합니까?",
            "알려진 CVE가 있는 컴포넌트를 즉시 패치하는 프로세스가 있습니까?",
            "SCA(Software Composition Analysis) 도구를 CI/CD에 통합했습니까?",
        ],
        "ref": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
    },
    {
        "id": "A07",
        "name": "인증 및 인증 실패 (Identification and Authentication Failures)",
        "questions": [
            "브루트포스 방어를 위한 계정 잠금 또는 CAPTCHA가 구현되어 있습니까?",
            "다중 인증(MFA)이 지원됩니까 (특히 관리자 계정)?",
            "세션 ID가 로그인 후 재생성됩니까?",
            "비밀번호 복잡성 요구사항이 있습니까?",
        ],
        "ref": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    },
    {
        "id": "A08",
        "name": "소프트웨어 및 데이터 무결성 실패 (Software and Data Integrity Failures)",
        "questions": [
            "CI/CD 파이프라인에 무결성 검증이 포함되어 있습니까?",
            "외부 CDN/패키지의 무결성 해시(SRI)를 검증합니까?",
            "역직렬화 시 신뢰할 수 없는 데이터 소스를 차단합니까?",
        ],
        "ref": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    },
    {
        "id": "A09",
        "name": "보안 로깅 및 모니터링 실패 (Security Logging and Monitoring Failures)",
        "questions": [
            "로그인 실패, 권한 오류, 입력 검증 실패가 로깅됩니까?",
            "로그에 민감 정보(비밀번호, 토큰)가 포함되지 않습니까?",
            "보안 이벤트에 대한 알림/모니터링 체계가 있습니까?",
            "로그가 변조 방지된 원격 저장소에 보관됩니까?",
        ],
        "ref": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
    },
    {
        "id": "A10",
        "name": "서버측 요청 위조 (Server-Side Request Forgery, SSRF)",
        "questions": [
            "사용자가 제공한 URL로의 서버 요청 시 허용 목록(allowlist)을 사용합니까?",
            "내부 네트워크 주소(169.254.x.x, 10.x.x.x 등)로의 요청이 차단됩니까?",
            "URL 리다이렉트 추적이 비활성화되어 있습니까?",
        ],
        "ref": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
    },
]

results = {}

print("\n" + "=" * 60)
print("OWASP Top 10 2021 항목별 점검")
print("각 질문에 y(Pass) / n(Fail) / s(Skip/N-A) 로 답하세요")
print("=" * 60)

for cat in categories:
    print(f"\n[{cat['id']}] {cat['name']}")
    cat_results = []
    for i, q in enumerate(cat['questions'], 1):
        while True:
            ans = input(f"  Q{i}. {q}\n  -> ").strip().lower()
            if ans in ('y', 'n', 's', ''):
                break
            print("  y, n, s 중 하나를 입력하세요")
        status = {'y': 'PASS', 'n': 'FAIL', 's': 'N/A', '': 'N/A'}[ans]
        cat_results.append((q, status))
    results[cat['id']] = {'name': cat['name'], 'items': cat_results, 'ref': cat['ref']}

# 매트릭스 생성
with open(report_file, 'a') as f:
    f.write("## 컴플라이언스 매트릭스\n\n")
    f.write("| ID | 카테고리 | PASS | FAIL | N/A | 결과 |\n")
    f.write("|-----|---------|:----:|:----:|:---:|------|\n")

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
            overall = f"FAIL ({fails}건)"
            fail_items.append((cat_id, data))
        f.write(f"| {cat_id} | {data['name']} | {passes} | {fails} | {na} | {overall} |\n")

    f.write("\n## 실패 항목 개선 방안\n\n")
    if fail_items:
        for cat_id, data in fail_items:
            f.write(f"### {cat_id}: {data['name']}\n\n")
            f.write(f"**참조**: {data['ref']}\n\n")
            for q, s in data['items']:
                if s == 'FAIL':
                    f.write(f"- [ ] {q}\n")
            f.write("\n")
    else:
        f.write("실패 항목 없음\n\n")

print("\n[+] 점검 완료!")
PYEOF
```

### 3단계: 컴플라이언스 매트릭스 출력

```bash
echo ""
echo "=== 최종 컴플라이언스 매트릭스 ==="
grep -A 20 "## 컴플라이언스 매트릭스" "$REPORT_FILE" | head -20

FAIL_COUNT=$(grep -c "FAIL" "$REPORT_FILE" 2>/dev/null || echo 0)
echo ""
echo "[요약]"
echo "  총 실패 항목: $FAIL_COUNT"
echo "  상세 보고서: $REPORT_FILE"
```

### 4단계: 우선순위별 개선 권고 출력

```bash
echo ""
echo "=== 우선순위별 개선 권고 ==="
echo ""
echo "[높음] 즉시 조치 필요"
echo "  A01 접근 통제, A03 인젝션, A07 인증 실패 → 직접적인 데이터 유출 위험"
echo ""
echo "[중간] 단기 조치"
echo "  A02 암호화, A05 보안 설정, A06 취약 컴포넌트 → 패치/설정으로 해결 가능"
echo ""
echo "[낮음] 장기 계획"
echo "  A04 안전하지 않은 설계, A08 무결성, A09 로깅, A10 SSRF → 프로세스/아키텍처 개선"
echo ""
echo "[+] OWASP Top 10 전체 참조: https://owasp.org/Top10/"
echo "[+] 한국어 번역본: https://owasp.org/www-project-top-ten/"
```

## 완료 조건

- 10개 카테고리 모두 질의 완료
- `/tmp/owasp_check_<날짜>.md` 보고서에 컴플라이언스 매트릭스 저장됨
- FAIL 항목별 OWASP 참조 링크와 개선 체크리스트가 포함됨

## 실패 모드

| 문제 | 원인 | 해결책 |
|------|------|--------|
| 점검 중단 | 터미널 세션 종료 | 재실행 후 N/A(s)로 스킵 가능 |
| 결과 파일 없음 | `/tmp` 권한 문제 | `REPORT_FILE=~/owasp_result.md` 로 변경 |
| 질문 이해 어려움 | 기술 맥락 부족 | 각 참조 링크의 설명 섹션 참고 |

## 참고 사항

- N/A(s) 선택은 해당 질문이 현재 스택에 적용되지 않을 때 사용하세요. (예: SPA 앱에서 서버사이드 렌더링 관련 질문)
- 점검 결과는 보안팀 또는 개발팀과 공유하여 개선 로드맵 수립에 활용하세요.
- ISMS-P 인증 준비 중이라면 `isms-checklist` 스킬과 병행 점검을 권장합니다.
- 점검 결과는 공식 감사를 대체하지 않으며, 전문 침투 테스트와 병행하세요.
