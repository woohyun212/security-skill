---
name: ssl-check
description: Inspect SSL/TLS certificate validity, protocol versions, and cipher suites for a target host
license: MIT
metadata:
  category: web-security
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

`openssl s_client`와 `curl`을 사용해 대상 호스트의 SSL/TLS 설정을 종합적으로 점검합니다. 인증서 만료일·발급자·SAN(Subject Alternative Name) 확인, 프로토콜 버전 지원 여부(TLS 1.0/1.1 비활성화 여부), 암호화 스위트 목록, 인증서 체인 검증을 수행합니다.

## 언제 사용하나요

- 서버 TLS 설정의 보안 수준을 빠르게 점검할 때
- 인증서 만료 또는 잘못된 SAN으로 인한 연결 오류를 디버깅할 때
- 버그 바운티·침투 테스트에서 다운그레이드 공격 가능성을 확인할 때

## 사전 조건

- `openssl` 설치 필요 (대부분의 Linux/macOS에 기본 내장)
- `curl` 설치 필요
- 대상 호스트의 443번 포트(또는 지정 포트)에 대한 네트워크 접근

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `HOST` | 점검할 호스트명 | `example.com` |
| `PORT` | TLS 포트 (기본값 443) | `443` |

## 워크플로우

### 1단계: 인증서 정보 수집

```bash
HOST="example.com"
PORT="443"

echo "=== 인증서 정보 ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | openssl x509 -noout \
  -subject -issuer -dates -fingerprint -ext subjectAltName

echo ""
echo "=== 인증서 만료까지 남은 일수 ==="
EXPIRY=$(echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | openssl x509 -noout -enddate 2>/dev/null \
  | cut -d= -f2)

if [ -n "$EXPIRY" ]; then
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
  if [ "$DAYS_LEFT" -lt 30 ]; then
    echo "[WARNING] 인증서 만료 임박: ${DAYS_LEFT}일 남음 (만료: $EXPIRY)"
  else
    echo "[OK] 인증서 유효: ${DAYS_LEFT}일 남음 (만료: $EXPIRY)"
  fi
fi
```

### 2단계: 프로토콜 버전 지원 여부 테스트

```bash
echo ""
echo "=== 프로토콜 지원 여부 ==="

test_protocol() {
  local proto="$1"
  local flag="$2"
  result=$(echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    "$flag" 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "[ENABLED]  $proto  ← 활성화됨"
  else
    echo "[DISABLED] $proto"
  fi
}

test_protocol "TLS 1.0" "-tls1"
test_protocol "TLS 1.1" "-tls1_1"
test_protocol "TLS 1.2" "-tls1_2"
test_protocol "TLS 1.3" "-tls1_3"

echo ""
echo "※ TLS 1.0 / 1.1 은 [DISABLED] 이어야 안전합니다."
```

### 3단계: 협상된 암호화 스위트 확인

```bash
echo ""
echo "=== 협상된 암호화 스위트 ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | grep "Cipher is"

echo ""
echo "=== 서버가 제공하는 암호화 스위트 목록 (nmap 필요 시 대체 사용) ==="
# openssl ciphers 로 알려진 약한 스위트 확인
WEAK_CIPHERS="RC4:DES:3DES:MD5:NULL:EXPORT:aNULL:eNULL"
echo "약한 스위트 목록 테스트 중..."
for cipher in $(openssl ciphers "$WEAK_CIPHERS" 2>/dev/null | tr ':' ' '); do
  result=$(echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    -cipher "$cipher" 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "[WEAK CIPHER ACCEPTED] $cipher"
  fi
done
echo "약한 스위트 테스트 완료"
```

### 4단계: 인증서 체인 검증

```bash
echo ""
echo "=== 인증서 체인 검증 ==="
echo | openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "$HOST" \
  2>/dev/null | grep -E "verify return|Verify return code|Certificate chain"

echo ""
echo "=== curl 을 통한 종합 TLS 검증 ==="
curl -sv --max-time 10 "https://${HOST}/" 2>&1 \
  | grep -E "SSL connection|TLSv|cipher|issuer|expire|subject|verify"
```

## 완료 조건

- 인증서 만료일 및 남은 일수가 출력됨
- TLS 1.0/1.1/1.2/1.3 각각의 활성화 여부가 판정됨
- 협상된 암호화 스위트가 표시되고, 알려진 약한 스위트 수용 여부가 확인됨
- 인증서 체인 검증 결과(verify return code)가 출력됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| `connect: Connection refused` | 포트 닫힘. PORT 변수 확인 |
| `verify error:num=18:self signed certificate` | 자체 서명 인증서. 의도적인 경우 아니라면 CA 서명 인증서 필요 |
| TLS 1.3 테스트 실패 | 시스템 openssl 버전이 1.3 미지원. `openssl version` 으로 확인 |
| 약한 스위트 테스트가 오래 걸림 | 타임아웃 추가: `timeout 3 openssl s_client ...` |

## 참고

- 더 상세한 분석이 필요하면 `testssl.sh` (https://testssl.sh) 사용 권장.
- SNI를 지원하지 않는 서버는 `-servername` 없이 테스트 필요.
- 포트 25/587/143 등 STARTTLS 서비스는 `-starttls smtp` 등 플래그 추가.
