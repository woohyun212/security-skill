---
name: security-headers
description: Analyze HTTP security headers of a target URL and provide remediation advice
license: MIT
metadata:
  category: web-security
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

대상 URL에 HTTP 요청을 보내 응답 헤더를 수집하고, 보안 관련 헤더의 존재 여부와 설정 적절성을 검사합니다. 각 헤더를 present / missing / misconfigured 중 하나로 판정하고, 누락되거나 잘못 설정된 헤더에 대해 수정 권고안을 제시합니다.

## 언제 사용하나요

- 웹 애플리케이션 보안 점검(초기 정찰 단계)을 수행할 때
- 배포 전 보안 체크리스트를 실행할 때
- 버그 바운티 또는 침투 테스트에서 헤더 취약점을 빠르게 확인할 때

## 사전 조건

- `curl` 설치 필요 (대부분의 Linux/macOS에 기본 내장)
- 대상 서버에 대한 HTTP/HTTPS 접근 권한

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `TARGET_URL` | 점검할 대상 URL (스킴 포함) | `https://example.com` |

## 워크플로우

### 1단계: 응답 헤더 수집

```bash
TARGET_URL="https://example.com"

curl -s -I -L \
  --max-time 10 \
  --user-agent "SecurityHeadersCheck/1.0" \
  "$TARGET_URL" 2>&1 | tee /tmp/headers_raw.txt

echo "=== 수집된 헤더 ==="
cat /tmp/headers_raw.txt
```

### 2단계: 개별 보안 헤더 검사

```bash
check_header() {
  local name="$1"
  local pattern="$2"
  local value
  value=$(grep -i "^${pattern}:" /tmp/headers_raw.txt | head -1)
  if [ -z "$value" ]; then
    echo "[MISSING]  $name"
  else
    echo "[PRESENT]  $value"
  fi
}

echo ""
echo "=== 보안 헤더 점검 결과 ==="
check_header "X-Content-Type-Options"    "x-content-type-options"
check_header "X-Frame-Options"           "x-frame-options"
check_header "Strict-Transport-Security" "strict-transport-security"
check_header "Content-Security-Policy"   "content-security-policy"
check_header "X-XSS-Protection"          "x-xss-protection"
check_header "Referrer-Policy"           "referrer-policy"
check_header "Permissions-Policy"        "permissions-policy"
```

### 3단계: 잘못된 설정 탐지

```bash
echo ""
echo "=== 설정 오류 검사 ==="

# HSTS: max-age 가 너무 짧으면 경고
hsts=$(grep -i "^strict-transport-security:" /tmp/headers_raw.txt | head -1)
if [ -n "$hsts" ]; then
  max_age=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+')
  if [ -n "$max_age" ] && [ "$max_age" -lt 31536000 ]; then
    echo "[MISCONFIGURED] HSTS max-age=$max_age (권장: 31536000 이상)"
  else
    echo "[OK] HSTS max-age 충분"
  fi
fi

# X-XSS-Protection: 1; mode=block 이 아니면 경고
xxp=$(grep -i "^x-xss-protection:" /tmp/headers_raw.txt | head -1)
if [ -n "$xxp" ]; then
  if echo "$xxp" | grep -qi "0"; then
    echo "[MISCONFIGURED] X-XSS-Protection: 0 으로 비활성화됨"
  fi
fi

# X-Frame-Options: ALLOW-FROM 은 구식 방식
xfo=$(grep -i "^x-frame-options:" /tmp/headers_raw.txt | head -1)
if [ -n "$xfo" ]; then
  if echo "$xfo" | grep -qi "allow-from"; then
    echo "[MISCONFIGURED] X-Frame-Options ALLOW-FROM 은 대부분 브라우저에서 미지원. CSP frame-ancestors 사용 권장"
  fi
fi
```

### 4단계: 수정 권고안 출력

```bash
echo ""
echo "=== 수정 권고안 ==="

grep -qi "^x-content-type-options:" /tmp/headers_raw.txt || \
  echo "X-Content-Type-Options: nosniff  # MIME 타입 스니핑 방지"

grep -qi "^x-frame-options:" /tmp/headers_raw.txt || \
  echo "X-Frame-Options: DENY  # 클릭재킹 방지 (또는 Content-Security-Policy: frame-ancestors 'none')"

grep -qi "^strict-transport-security:" /tmp/headers_raw.txt || \
  echo "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload  # HTTPS 강제"

grep -qi "^content-security-policy:" /tmp/headers_raw.txt || \
  echo "Content-Security-Policy: default-src 'self'  # XSS/데이터 삽입 공격 방지 (정책은 애플리케이션에 맞게 조정)"

grep -qi "^referrer-policy:" /tmp/headers_raw.txt || \
  echo "Referrer-Policy: strict-origin-when-cross-origin  # Referer 헤더 정보 노출 제한"

grep -qi "^permissions-policy:" /tmp/headers_raw.txt || \
  echo "Permissions-Policy: geolocation=(), microphone=(), camera=()  # 브라우저 기능 제한"

echo ""
echo "참고: https://securityheaders.com 에서 상세 등급 확인 가능"
```

## 완료 조건

- 7개 보안 헤더 각각에 대해 present / missing / misconfigured 판정이 출력됨
- 누락/잘못된 헤더에 대한 구체적인 헤더 값 예시가 제시됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| `curl: (6) Could not resolve host` | DNS 미해결. URL 및 네트워크 연결 확인 |
| `curl: (60) SSL certificate problem` | 자체 서명 인증서. `-k` 플래그 추가 (테스트 환경 한정) |
| 헤더가 비어 있음 | CDN/프록시 뒤에서 헤더를 제거할 수 있음. 원본 서버 직접 점검 고려 |
| 302/301 리디렉션 후 헤더 다름 | `-L` 플래그로 최종 목적지 헤더까지 추적 |

## 참고

- `Content-Security-Policy`는 정책이 복잡하므로 누락으로 판정해도 단순 권고에 그침. 실제 구성은 애플리케이션별로 검토 필요.
- `X-XSS-Protection`은 최신 브라우저에서 사용 중단(deprecated)됨. 새 프로젝트는 CSP 사용 권장.
- HTTPS 미사용 사이트는 HSTS 적용 불가.
