---
name: cert-transparency
description: Certificate Transparency log search via crt.sh API to discover subdomains and certificates
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

crt.sh의 Certificate Transparency(CT) 로그 API를 통해 특정 도메인에 발급된 TLS/SSL 인증서를 조회합니다. 인증서의 CN(Common Name) 및 SAN(Subject Alternative Name) 필드에서 서브도메인을 추출하고 중복을 제거하여 공격 표면을 확장합니다.

## 언제 사용하나

- 패시브 방식으로 서브도메인을 열거할 때 (DNS 쿼리 없음)
- 와일드카드 인증서 하위 도메인을 탐색할 때
- 특정 조직에서 발급한 인증서 목록을 감사할 때
- subfinder/amass 결과를 보완하는 추가 소스가 필요할 때

## 사전 조건

- `curl` 설치:
  ```bash
  sudo apt-get install -y curl
  ```
- `jq` 설치 (JSON 파싱):
  ```bash
  sudo apt-get install -y jq
  ```
- 외부 인터넷 접속 가능 (crt.sh API 호출)
- 환경 변수 `SECSKILL_TARGET_DOMAIN`: 조회할 도메인

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET_DOMAIN` | 필수 | 조회할 루트 도메인 (예: `example.com`) |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_INCLUDE_EXPIRED` | 선택 | `true`로 설정 시 만료 인증서 포함 (기본: `false`) |

## 워크플로우

### 1단계: 환경 준비

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?SECSKILL_TARGET_DOMAIN 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export INCLUDE_EXPIRED="${SECSKILL_INCLUDE_EXPIRED:-false}"
mkdir -p "$OUTDIR"
echo "[*] Certificate Transparency 조회 시작: $TARGET"
```

### 2단계: crt.sh API 조회

```bash
echo "[*] crt.sh API 조회 중..."
CRT_URL="https://crt.sh/?q=%.${TARGET}&output=json"

RAW_JSON="$OUTDIR/crt_raw_${TARGET}.json"

HTTP_CODE=$(curl -s -o "$RAW_JSON" -w "%{http_code}" \
  --max-time 30 \
  --retry 3 \
  --retry-delay 5 \
  "$CRT_URL")

if [ "$HTTP_CODE" != "200" ]; then
  echo "[-] crt.sh API 오류 (HTTP $HTTP_CODE). 잠시 후 재시도하세요."
  exit 1
fi

CERT_COUNT=$(jq 'length' "$RAW_JSON" 2>/dev/null || echo "0")
echo "[+] 발견된 인증서 수: $CERT_COUNT"
```

### 3단계: 서브도메인 추출 및 중복 제거

```bash
echo "[*] 서브도메인 추출 중..."
SUBDOMAINS_FILE="$OUTDIR/ct_subdomains_${TARGET}.txt"

jq -r '.[].name_value' "$RAW_JSON" 2>/dev/null \
  | tr ',' '\n' \
  | sed 's/^\*\.//' \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E "\\.${TARGET}$|^${TARGET}$" \
  | sort -u \
  > "$SUBDOMAINS_FILE"

SUB_COUNT=$(wc -l < "$SUBDOMAINS_FILE")
echo "[+] 고유 서브도메인: $SUB_COUNT 개"
```

### 4단계: 만료되지 않은 인증서만 필터링 (선택)

```bash
if [ "$INCLUDE_EXPIRED" != "true" ]; then
  echo "[*] 유효한 인증서에서만 서브도메인 추출 중..."
  VALID_SUBDOMAINS_FILE="$OUTDIR/ct_valid_subdomains_${TARGET}.txt"

  NOW=$(date -u '+%Y-%m-%dT%H:%M:%S')
  jq -r --arg now "$NOW" \
    '.[] | select(.not_after > $now) | .name_value' "$RAW_JSON" 2>/dev/null \
    | tr ',' '\n' \
    | sed 's/^\*\.//' \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E "\\.${TARGET}$|^${TARGET}$" \
    | sort -u \
    > "$VALID_SUBDOMAINS_FILE"

  VALID_COUNT=$(wc -l < "$VALID_SUBDOMAINS_FILE")
  echo "[+] 유효 인증서 기반 서브도메인: $VALID_COUNT 개"
fi
```

### 5단계: 인증서 발급 기관 통계

```bash
echo ""
echo "===== 인증서 발급 기관 통계 ====="
jq -r '.[].issuer_name' "$RAW_JSON" 2>/dev/null \
  | grep -oP '(?<=O=)[^,]+' \
  | sort | uniq -c | sort -rn | head -10
echo "=================================="
```

### 6단계: 와일드카드 인증서 식별

```bash
echo ""
echo "===== 와일드카드 인증서 목록 ====="
jq -r '.[].name_value' "$RAW_JSON" 2>/dev/null \
  | tr ',' '\n' \
  | grep '^\*\.' \
  | sort -u \
  | head -20
echo "==================================="
```

### 7단계: 결과 요약

```bash
echo ""
echo "===== Certificate Transparency 결과 요약 ====="
echo "대상 도메인     : $TARGET"
echo "발견 인증서 수  : $CERT_COUNT"
echo "고유 서브도메인 : $SUB_COUNT 개"
echo "결과 파일       : $SUBDOMAINS_FILE"
echo "원본 JSON       : $RAW_JSON"
echo "=============================================="
```

## 완료 조건

- crt.sh API 응답이 HTTP 200이다
- 서브도메인 목록 파일이 생성된다
- 추출된 서브도메인 수가 출력된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| HTTP 503 오류 | crt.sh 서버 과부하 | 수분 후 재시도 |
| `jq: command not found` | jq 미설치 | `apt-get install jq` 실행 |
| 결과가 0개 | 신규 도메인 또는 CT 미제출 | 도메인 확인, `subdomain-enum` 스킬 병행 |
| JSON 파싱 오류 | API 응답 형식 변경 | `cat $RAW_JSON` 으로 원본 확인 |
| 타임아웃 | 네트워크 지연 | `--max-time` 값 증가 (60초 이상) |

## 참고

- CT 로그는 공개 데이터로, 인증을 요구하지 않습니다.
- 와일드카드 인증서(`*.example.com`)는 수천 개의 서브도메인을 커버할 수 있습니다.
- 만료된 인증서도 과거 인프라 구조 파악에 유용합니다.
- 추출된 서브도메인은 `subdomain-enum` 스킬 결과와 병합하면 더 완전한 목록을 얻을 수 있습니다.
- crt.sh 외 Censys (`https://censys.io`), Facebook CT API도 보완적으로 활용 가능합니다.
