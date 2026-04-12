---
name: osint-email
description: Email-based OSINT collection including breach database checks and social account enumeration
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

이메일 주소를 기반으로 OSINT 정보를 수집합니다. 이메일 형식 유효성 검사, Have I Been Pwned API를 통한 데이터 유출 이력 확인, holehe를 활용한 소셜/서비스 계정 존재 여부 탐지를 수행합니다.

## 언제 사용하나

- 피싱 시뮬레이션 전 대상 이메일의 노출 이력을 파악할 때
- 직원 이메일이 데이터 유출에 포함되었는지 확인할 때
- 소셜 엔지니어링 공격 가능성을 평가할 때
- 개인 또는 조직의 디지털 발자국을 감사할 때

## 사전 조건

- `curl` 설치
- holehe 설치 (소셜 계정 확인):
  ```bash
  pip install holehe
  ```
- Have I Been Pwned API 키 발급: https://haveibeenpwned.com/API/Key
- 환경 변수 설정:
  - `SECSKILL_TARGET_EMAIL`: 조회할 이메일 주소
  - `SECSKILL_HIBP_API_KEY`: Have I Been Pwned API 키

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET_EMAIL` | 필수 | 조회할 이메일 주소 |
| `SECSKILL_HIBP_API_KEY` | 필수 | HIBP API 키 (유출 이력 확인용) |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_RUN_HOLEHE` | 선택 | `true`로 설정 시 holehe 실행 (기본: `false`) |

## 워크플로우

### 1단계: 이메일 형식 유효성 검사

```bash
export EMAIL="${SECSKILL_TARGET_EMAIL:?SECSKILL_TARGET_EMAIL 환경 변수를 설정하세요}"
export HIBP_KEY="${SECSKILL_HIBP_API_KEY:-}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export RUN_HOLEHE="${SECSKILL_RUN_HOLEHE:-false}"
mkdir -p "$OUTDIR"

SAFE_EMAIL=$(echo "$EMAIL" | tr '@.' '__')
OUTFILE="$OUTDIR/osint_email_${SAFE_EMAIL}.txt"

echo "===== 이메일 OSINT: $EMAIL =====" > "$OUTFILE"
echo "조회 시각: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"

# 형식 검증
if echo "$EMAIL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
  echo "[+] 이메일 형식 유효: $EMAIL" | tee -a "$OUTFILE"
  DOMAIN=$(echo "$EMAIL" | cut -d'@' -f2)
  USER=$(echo "$EMAIL" | cut -d'@' -f1)
  echo "[*] 도메인: $DOMAIN | 사용자: $USER"
else
  echo "[-] 유효하지 않은 이메일 형식: $EMAIL"
  exit 1
fi
```

### 2단계: Have I Been Pwned - 유출 이력 확인

```bash
echo "" >> "$OUTFILE"
echo "--- Have I Been Pwned 유출 이력 ---" | tee -a "$OUTFILE"

if [ -z "$HIBP_KEY" ]; then
  echo "[-] SECSKILL_HIBP_API_KEY 미설정. HIBP 확인을 건너뜁니다." | tee -a "$OUTFILE"
else
  ENCODED_EMAIL=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$EMAIL'))")
  HIBP_RESPONSE=$(curl -s \
    -H "hibp-api-key: $HIBP_KEY" \
    -H "user-agent: SecuritySkill-OSINT/1.0" \
    --max-time 15 \
    "https://haveibeenpwned.com/api/v3/breachedaccount/${ENCODED_EMAIL}?truncateResponse=false")

  HTTP_STATUS=$?
  if echo "$HIBP_RESPONSE" | grep -q '"Name"'; then
    BREACH_COUNT=$(echo "$HIBP_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))")
    echo "[!] 유출 이력 발견: $BREACH_COUNT 건" | tee -a "$OUTFILE"
    echo "$HIBP_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for breach in data:
    print(f\"  - {breach['Name']} ({breach['BreachDate']}): {', '.join(breach['DataClasses'][:5])}\")
" | tee -a "$OUTFILE"
  elif echo "$HIBP_RESPONSE" | grep -q "404"; then
    echo "[+] 유출 이력 없음 (데이터베이스에서 발견되지 않음)" | tee -a "$OUTFILE"
  else
    echo "[-] HIBP API 응답 오류. API 키 또는 네트워크를 확인하세요." | tee -a "$OUTFILE"
  fi
fi
```

### 3단계: Have I Been Pwned - 페이스트 확인

```bash
if [ -n "$HIBP_KEY" ]; then
  echo "" >> "$OUTFILE"
  echo "--- Paste 데이터베이스 확인 ---" | tee -a "$OUTFILE"

  ENCODED_EMAIL=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$EMAIL'))")
  PASTE_RESPONSE=$(curl -s \
    -H "hibp-api-key: $HIBP_KEY" \
    -H "user-agent: SecuritySkill-OSINT/1.0" \
    --max-time 15 \
    "https://haveibeenpwned.com/api/v3/pasteaccount/${ENCODED_EMAIL}")

  if echo "$PASTE_RESPONSE" | grep -q '"Source"'; then
    PASTE_COUNT=$(echo "$PASTE_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))")
    echo "[!] Paste 사이트 노출: $PASTE_COUNT 건" | tee -a "$OUTFILE"
    echo "$PASTE_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for paste in data[:10]:
    print(f\"  - {paste['Source']}: {paste.get('Title','(제목 없음)')} ({paste.get('Date','날짜 불명')})\")
" | tee -a "$OUTFILE"
  else
    echo "[+] Paste 사이트 노출 없음" | tee -a "$OUTFILE"
  fi
fi
```

### 4단계: 이메일 도메인 MX 레코드 확인

```bash
echo "" >> "$OUTFILE"
echo "--- 이메일 도메인 DNS 확인 ---" | tee -a "$OUTFILE"

MX=$(dig "$DOMAIN" MX +short 2>/dev/null | sort)
if [ -n "$MX" ]; then
  echo "[+] MX 레코드 유효 - 실제 이메일 수신 가능" | tee -a "$OUTFILE"
  echo "$MX" | tee -a "$OUTFILE"
else
  echo "[-] MX 레코드 없음 - 이메일 주소가 유효하지 않을 수 있음" | tee -a "$OUTFILE"
fi
```

### 5단계: holehe로 소셜 계정 확인 (선택)

```bash
if [ "$RUN_HOLEHE" = "true" ]; then
  echo "" >> "$OUTFILE"
  echo "--- holehe 소셜 계정 확인 ---" | tee -a "$OUTFILE"

  if command -v holehe >/dev/null 2>&1; then
    echo "[*] holehe 실행 중 (수십 초 소요)..."
    holehe --only-used "$EMAIL" 2>/dev/null \
      | grep -E "^\[|\[\+\]|\[-\]" \
      | tee -a "$OUTFILE"
    echo "[+] holehe 완료"
  else
    echo "[-] holehe 미설치. 설치: pip install holehe" | tee -a "$OUTFILE"
  fi
else
  echo "[*] holehe 건너뜀 (SECSKILL_RUN_HOLEHE=true 로 활성화 가능)"
fi
```

### 6단계: 결과 요약

```bash
echo ""
echo "===== 이메일 OSINT 결과 요약 ====="
echo "대상 이메일: $EMAIL"
echo "결과 파일  : $OUTFILE"
echo "=================================="
cat "$OUTFILE"
```

## 완료 조건

- 이메일 형식 유효성 검사가 완료된다
- HIBP API 호출 결과가 기록된다 (키 제공 시)
- holehe 결과가 기록된다 (`SECSKILL_RUN_HOLEHE=true` 시)
- 결과 파일이 생성된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| HIBP 401 오류 | 잘못된 API 키 | HIBP 대시보드에서 키 재확인 |
| HIBP 429 오류 | 레이트 리밋 초과 | 1분 후 재시도 (API는 1.5초 간격 제한) |
| holehe 오류 | 패키지 의존성 문제 | `pip install --upgrade holehe` |
| MX 레코드 없음 | 무효 도메인 | 이메일 주소 재확인 |

## 참고

- HIBP API는 유료($3.50/월)이지만 개인 사용은 저렴합니다.
- holehe는 100개 이상의 서비스에 대해 계정 존재 여부를 확인합니다 (비밀번호 시도 없음).
- 본인 또는 명시적 동의를 받은 대상에만 사용해야 합니다.
- 수집된 정보는 안전하게 보관하고, 보고서 작성 후 불필요한 개인정보는 삭제하세요.
- GDPR, CCPA 등 개인정보 보호법 준수가 필요합니다.
