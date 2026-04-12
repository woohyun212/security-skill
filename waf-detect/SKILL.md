---
name: waf-detect
description: Detect the presence and type of a Web Application Firewall using wafw00f or manual fingerprinting
license: MIT
metadata:
  category: web-security
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

`wafw00f` 도구 또는 수동 curl 핑거프린팅을 통해 대상 URL 앞에 WAF(Web Application Firewall)가 있는지 탐지하고, Cloudflare·AWS WAF·Akamai·F5 BIG-IP 등 주요 WAF의 종류를 식별합니다.

## 언제 사용하나요

- 침투 테스트·버그 바운티 초기 정찰 단계에서 WAF 우회 전략 수립 전
- 내 서비스의 WAF가 올바르게 작동하는지 확인할 때
- 스캐너 오탐/미탐 원인으로 WAF를 의심할 때

## 사전 조건

- Python 3 및 pip 설치 필요 (`wafw00f` 설치 시)
- `curl` 설치 필요 (수동 방법 fallback)
- 대상 URL에 대한 HTTP/HTTPS 접근 권한

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `TARGET_URL` | 점검할 대상 URL | `https://example.com` |

## 워크플로우

### 1단계: wafw00f 설치 (미설치 시)

```bash
# wafw00f 존재 여부 확인 후 설치
if ! command -v wafw00f &>/dev/null; then
  echo "wafw00f 미설치. 설치 중..."
  pip install wafw00f --quiet
else
  echo "wafw00f 이미 설치됨: $(wafw00f --version 2>&1 | head -1)"
fi
```

### 2단계: wafw00f 로 WAF 탐지

```bash
TARGET_URL="https://example.com"

echo "=== wafw00f WAF 탐지 ==="
wafw00f "$TARGET_URL" -a 2>&1
# -a : 여러 WAF 후보 모두 출력
```

### 3단계: wafw00f 사용 불가 시 수동 핑거프린팅

```bash
echo ""
echo "=== 수동 WAF 핑거프린팅 (curl) ==="

# 1) 정상 요청으로 베이스라인 헤더 수집
echo "--- 정상 요청 ---"
NORMAL=$(curl -s -I "$TARGET_URL" --max-time 10 2>&1)
echo "$NORMAL" | grep -iE "server:|x-powered-by:|cf-ray:|x-amz|x-cache|x-cdn|via:|x-sucuri|x-fw-|x-waf"

# 2) 악성 페이로드 요청으로 WAF 반응 유도
echo ""
echo "--- 페이로드 요청 (WAF 반응 확인) ---"
ATTACK=$(curl -s -o /dev/null -w "%{http_code}" \
  "$TARGET_URL/?q=<script>alert(1)</script>" \
  --max-time 10 2>&1)
echo "XSS 페이로드 HTTP 상태: $ATTACK"

SQLI=$(curl -s -o /dev/null -w "%{http_code}" \
  "$TARGET_URL/?id=1'+OR+'1'='1" \
  --max-time 10 2>&1)
echo "SQLi 페이로드 HTTP 상태: $SQLI"

HEADERS_ATTACK=$(curl -s -I \
  "$TARGET_URL/?q=<script>alert(1)</script>" \
  --max-time 10 2>&1)
echo ""
echo "--- 페이로드 요청 응답 헤더 ---"
echo "$HEADERS_ATTACK" | grep -iE "server:|cf-ray:|x-amz|x-cache|x-sucuri|x-iinfo:|x-check-cacheable:|x-fw-|set-cookie:"
```

### 4단계: 주요 WAF 핑거프린트 패턴 비교

```bash
echo ""
echo "=== WAF 핑거프린트 패턴 참조 ==="
cat <<'EOF'
Cloudflare
  헤더: CF-RAY, Server: cloudflare
  차단 응답: 403/503 + "Cloudflare" 본문, "__cf_bm" 쿠키

AWS WAF
  헤더: x-amzn-requestid, x-amz-cf-id
  차단 응답: 403 + "AWS" 또는 "Request blocked"

Akamai
  헤더: X-Check-Cacheable, X-Akamai-*, Server: AkamaiGHost
  차단 응답: 403 + Reference #

F5 BIG-IP ASM
  헤더: X-WA-Info, Set-Cookie: TS (TS로 시작하는 쿠키)
  차단 응답: 정책 차단 페이지

Sucuri
  헤더: X-Sucuri-ID, Server: Sucuri/Cloudproxy
  차단 응답: 403 + Sucuri 로고 페이지

ModSecurity (오픈소스)
  헤더: Server에 mod_security 또는 특별 헤더 없음
  차단 응답: 403 + "ModSecurity" 본문 또는 커스텀 에러 페이지
EOF

echo ""
echo "=== 탐지 요약 ==="
echo "정상 응답 코드: $(echo "$NORMAL" | grep "^HTTP" | awk '{print $2}')"
echo "XSS 페이로드 차단 여부: $ATTACK"
echo "SQLi 페이로드 차단 여부: $SQLI"
```

## 완료 조건

- WAF 존재 여부(있음/없음/불명확)가 판정됨
- 가능한 경우 WAF 제품명이 식별됨
- 정상 요청 대비 페이로드 요청의 HTTP 상태 코드 차이가 기록됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| wafw00f 설치 실패 | pip 권한 문제. `pip install --user wafw00f` 또는 가상환경 사용 |
| 모든 페이로드가 200 반환 | WAF 없거나 탐지 우회됨. URL 인코딩 변형 시도 |
| 403이지만 WAF 헤더 없음 | 애플리케이션 레벨 차단일 수 있음. 응답 본문 확인 필요 |
| Rate limit으로 IP 차단 | 요청 간격 조절: `sleep 2` 추가 |

## 참고

- wafw00f 는 140개 이상의 WAF를 식별할 수 있음 (https://github.com/EnableSecurity/wafw00f).
- WAF 우회 기법 연구에는 `identYwaf`(https://github.com/stamparm/identYwaf) 도 활용 가능.
- 탐지 결과가 "No WAF detected"여도 WAF가 없다고 단정할 수 없음. 스텔스 모드 WAF는 탐지 회피 가능.
