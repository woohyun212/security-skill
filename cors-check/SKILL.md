---
name: cors-check
description: Detect CORS misconfiguration by testing various Origin headers and analyzing Access-Control responses
license: MIT
metadata:
  category: web-security
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

다양한 `Origin` 헤더 값을 포함한 HTTP 요청을 대상 URL에 전송해 CORS(Cross-Origin Resource Sharing) 정책의 취약점을 탐지합니다. `Access-Control-Allow-Origin`이 요청 Origin을 그대로 반영하거나, `null`을 허용하거나, `*`와 `Access-Control-Allow-Credentials: true`를 동시에 설정하는 등의 잘못된 구성을 식별합니다.

## 언제 사용하나요

- API 엔드포인트의 CORS 정책을 점검할 때
- 크로스 사이트 요청 위조(CSRF) 또는 자격증명 탈취 가능성을 확인할 때
- 버그 바운티에서 CORS 기반 계정 탈취 취약점을 검증할 때

## 사전 조건

- `curl` 설치 필요
- 대상 URL에 대한 HTTP/HTTPS 접근 권한

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `TARGET_URL` | 점검할 엔드포인트 URL | `https://api.example.com/user` |
| `LEGITIMATE_ORIGIN` | 정상 오리진 (알고 있는 경우) | `https://example.com` |

## 워크플로우

### 1단계: 기본 CORS 응답 확인

```bash
TARGET_URL="https://api.example.com/user"
LEGITIMATE_ORIGIN="https://example.com"

echo "=== 기본 CORS 헤더 확인 (Origin 없음) ==="
curl -s -I -X GET "$TARGET_URL" \
  --max-time 10 2>&1 \
  | grep -i "access-control"
```

### 2단계: 다양한 Origin 값으로 반사(reflection) 테스트

```bash
echo ""
echo "=== Origin 반사 테스트 ==="

test_cors() {
  local label="$1"
  local origin="$2"
  local response
  response=$(curl -s -I -X GET "$TARGET_URL" \
    -H "Origin: $origin" \
    --max-time 10 2>&1)

  local acao
  acao=$(echo "$response" | grep -i "access-control-allow-origin:" | tr -d '\r')
  local acac
  acac=$(echo "$response" | grep -i "access-control-allow-credentials:" | tr -d '\r')

  echo "--- [$label] Origin: $origin ---"
  echo "  ACAO: ${acao:-<없음>}"
  echo "  ACAC: ${acac:-<없음>}"

  # 위험 판정
  if echo "$acao" | grep -qi "$origin"; then
    if echo "$acac" | grep -qi "true"; then
      echo "  [CRITICAL] Origin 반사 + Credentials=true → 자격증명 탈취 가능"
    else
      echo "  [WARNING]  Origin 반사됨 (Credentials 없음)"
    fi
  fi
  if echo "$acao" | grep -q '^\s*[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:\s*\*'; then
    if echo "$acac" | grep -qi "true"; then
      echo "  [CRITICAL] ACAO=* + Credentials=true → 브라우저 차단하지만 잘못된 설정"
    else
      echo "  [INFO]     ACAO=* (와일드카드, 인증 없는 공개 API는 허용 가능)"
    fi
  fi
  echo ""
}

test_cors "정상 오리진"          "$LEGITIMATE_ORIGIN"
test_cors "null Origin"          "null"
test_cors "공격자 도메인"        "https://attacker.com"
test_cors "서브도메인"           "https://sub.example.com"
test_cors "접두사 유사 도메인"   "https://example.com.evil.com"
test_cors "후미 슬래시 변형"     "${LEGITIMATE_ORIGIN}/"
test_cors "HTTP 다운그레이드"    "http://example.com"
```

### 3단계: Preflight(OPTIONS) 요청 테스트

```bash
echo "=== Preflight OPTIONS 요청 테스트 ==="
curl -s -I -X OPTIONS "$TARGET_URL" \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \
  --max-time 10 2>&1 \
  | grep -i "access-control"
```

### 4단계: 결과 요약 및 위험도 평가

```bash
echo ""
echo "=== 위험도 판정 기준 ==="
cat <<'EOF'
[CRITICAL]  ACAO가 요청 Origin을 반사 + ACAC: true
            → 공격자가 인증된 API 요청을 크로스 사이트에서 실행 가능

[HIGH]      ACAO: null + ACAC: true
            → 샌드박스 iframe 또는 로컬 파일에서 악용 가능

[MEDIUM]    ACAO가 요청 Origin을 반사 (ACAC 없음)
            → 민감 데이터 응답이라면 위험

[LOW/INFO]  ACAO: * (와일드카드, ACAC 없음)
            → 공개 API에는 의도된 동작일 수 있음

수정 권고:
  - 허용 Origin을 화이트리스트로 고정 (동적 반사 금지)
  - credentials=true 사용 시 와일드카드(*) 사용 불가
  - null Origin 허용 금지
  - Vary: Origin 헤더 추가 (캐시 오염 방지)
EOF
```

## 완료 조건

- 8가지 이상의 Origin 변형에 대해 ACAO/ACAC 응답이 출력됨
- 위험한 구성(반사+Credentials, null Origin 허용 등)이 자동으로 탐지되어 표시됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| 모든 테스트에서 ACAO 헤더 없음 | CORS 정책 미설정 또는 동일 출처만 허용. 브라우저 동작과 별개로 curl 응답에는 없을 수 있음 |
| 302 리디렉션으로 원하는 응답 없음 | `-L` 플래그 추가하거나 최종 URL 직접 지정 |
| 서버가 OPTIONS 메서드 차단 | 405 응답은 Preflight 미지원을 의미. 단순 요청(GET/POST) 테스트로 대체 |

## 참고

- 브라우저는 `ACAO: * + ACAC: true` 조합을 차단하지만, 서버 설정 자체는 잘못된 것이므로 보고 대상.
- 서브도메인 XSS가 있다면 서브도메인 Origin 허용도 취약점이 될 수 있음.
- 자동화 도구: `corsy` (https://github.com/s0md3v/Corsy) 사용 고려.
