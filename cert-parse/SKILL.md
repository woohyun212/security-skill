---
name: cert-parse
description: Parse X.509 certificate details and verify certificate chain integrity
license: MIT
metadata:
  category: crypto
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

X.509 인증서 파일 또는 PEM 텍스트를 입력받아 `openssl x509`로 주체(Subject)·발급자(Issuer)·SAN·유효기간·공개키 정보·확장 필드를 파싱합니다. CA 번들이 제공되면 `openssl verify`로 체인 검증을 수행하고, 약한 키·만료·자체 서명 등 일반적인 문제를 자동으로 검사합니다.

## 언제 사용하나요

- 서버 인증서를 배포 전후에 점검할 때
- 인증서 체인 오류(UNABLE_TO_GET_ISSUER_CERT 등)를 디버깅할 때
- 버그 바운티·침투 테스트에서 인증서 관련 취약점(약한 키, 와일드카드 오용 등)을 확인할 때

## 사전 조건

- `openssl` 설치 필요 (Linux/macOS 기본 내장)
- 인증서 파일(PEM/DER) 또는 PEM 텍스트
- 체인 검증 시 CA 번들 파일 (선택)

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `CERT_INPUT` | PEM 파일 경로 또는 원격 호스트 | `/path/to/cert.pem` 또는 `example.com:443` |
| `CA_BUNDLE` | (선택) CA 번들 파일 경로 | `/etc/ssl/certs/ca-certificates.crt` |

## 워크플로우

### 1단계: 인증서 소스에서 PEM 추출

```bash
CERT_INPUT="/path/to/cert.pem"  # 또는 "example.com:443"
WORK_CERT="/tmp/target_cert.pem"

# 파일인지 호스트:포트인지 판별
if [ -f "$CERT_INPUT" ]; then
  echo "=== 파일에서 인증서 로드: $CERT_INPUT ==="
  # DER 형식을 PEM으로 자동 변환
  if openssl x509 -in "$CERT_INPUT" -noout 2>/dev/null; then
    cp "$CERT_INPUT" "$WORK_CERT"
    echo "PEM 형식 확인"
  else
    openssl x509 -in "$CERT_INPUT" -inform DER -out "$WORK_CERT" 2>/dev/null && \
      echo "DER → PEM 변환 완료" || echo "인증서 형식 파싱 실패"
  fi
else
  echo "=== 원격 호스트에서 인증서 수집: $CERT_INPUT ==="
  HOST=$(echo "$CERT_INPUT" | cut -d: -f1)
  PORT=$(echo "$CERT_INPUT" | cut -d: -f2)
  PORT=${PORT:-443}
  echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    2>/dev/null | openssl x509 -out "$WORK_CERT"
  echo "원격 인증서 저장: $WORK_CERT"
fi
```

### 2단계: 주요 인증서 정보 파싱

```bash
echo ""
echo "=== 인증서 상세 정보 ==="

echo "--- Subject (주체) ---"
openssl x509 -in "$WORK_CERT" -noout -subject

echo ""
echo "--- Issuer (발급자) ---"
openssl x509 -in "$WORK_CERT" -noout -issuer

echo ""
echo "--- 유효기간 ---"
openssl x509 -in "$WORK_CERT" -noout -dates

echo ""
echo "--- Subject Alternative Names (SAN) ---"
openssl x509 -in "$WORK_CERT" -noout -ext subjectAltName 2>/dev/null \
  || openssl x509 -in "$WORK_CERT" -text -noout | grep -A3 "Subject Alternative Name"

echo ""
echo "--- 공개키 정보 ---"
openssl x509 -in "$WORK_CERT" -noout -pubkey | openssl pkey -pubin -noout -text 2>/dev/null \
  || openssl x509 -in "$WORK_CERT" -noout -text | grep -A3 "Public Key Algorithm"

echo ""
echo "--- 서명 알고리즘 ---"
openssl x509 -in "$WORK_CERT" -noout -text | grep "Signature Algorithm" | head -2

echo ""
echo "--- 확장 필드 (Extensions) ---"
openssl x509 -in "$WORK_CERT" -noout -text \
  | sed -n '/X509v3 extensions/,/Signature Algorithm/p' \
  | head -40
```

### 3단계: 일반적인 문제 자동 검사

```bash
echo ""
echo "=== 자동 보안 검사 ==="

# 만료 여부 확인
EXPIRY=$(openssl x509 -in "$WORK_CERT" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [ "$DAYS_LEFT" -lt 0 ]; then
  echo "[CRITICAL] 인증서 만료됨 (${DAYS_LEFT#-}일 전)"
elif [ "$DAYS_LEFT" -lt 30 ]; then
  echo "[WARNING]  인증서 만료 임박: ${DAYS_LEFT}일 남음"
else
  echo "[OK]       인증서 유효: ${DAYS_LEFT}일 남음"
fi

# 자체 서명 여부 확인
SUBJECT=$(openssl x509 -in "$WORK_CERT" -noout -subject)
ISSUER=$(openssl x509 -in "$WORK_CERT" -noout -issuer)
if [ "$SUBJECT" = "$ISSUER" ]; then
  echo "[WARNING]  자체 서명 인증서 (Subject == Issuer)"
else
  echo "[OK]       CA 서명 인증서"
fi

# 키 길이 확인
KEY_INFO=$(openssl x509 -in "$WORK_CERT" -noout -text 2>/dev/null | grep "Public-Key:")
KEY_BITS=$(echo "$KEY_INFO" | grep -oP '\(\K[0-9]+(?= bit)')
if [ -n "$KEY_BITS" ]; then
  if [ "$KEY_BITS" -lt 2048 ]; then
    echo "[CRITICAL] 약한 RSA 키: ${KEY_BITS}비트 (최소 2048비트 권장)"
  elif [ "$KEY_BITS" -lt 4096 ]; then
    echo "[INFO]     RSA 키: ${KEY_BITS}비트 (현재 수준 허용, 4096비트 권장)"
  else
    echo "[OK]       RSA 키: ${KEY_BITS}비트"
  fi
fi

# MD5/SHA1 서명 알고리즘 확인
SIG_ALG=$(openssl x509 -in "$WORK_CERT" -noout -text | grep "Signature Algorithm" | head -1)
if echo "$SIG_ALG" | grep -qi "md5\|sha1"; then
  echo "[CRITICAL] 취약한 서명 알고리즘: $SIG_ALG"
else
  echo "[OK]       서명 알고리즘: $SIG_ALG"
fi

# 와일드카드 인증서 확인
WILD=$(openssl x509 -in "$WORK_CERT" -noout -text | grep "\*\.")
if [ -n "$WILD" ]; then
  echo "[INFO]     와일드카드 인증서 감지: $WILD"
fi
```

### 4단계: 인증서 체인 검증 (CA 번들 제공 시)

```bash
CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"  # 또는 사용자 지정 CA 번들

echo ""
echo "=== 인증서 체인 검증 ==="
if [ -f "$CA_BUNDLE" ]; then
  openssl verify -CAfile "$CA_BUNDLE" "$WORK_CERT" 2>&1
else
  echo "CA 번들 없음. 시스템 기본 CA로 검증 시도..."
  openssl verify "$WORK_CERT" 2>&1
fi

echo ""
echo "=== 전체 인증서 텍스트 출력 (선택) ==="
echo "전체 출력이 필요하면 다음 명령어 실행:"
echo "  openssl x509 -in $WORK_CERT -text -noout"
```

## 완료 조건

- Subject·Issuer·SAN·유효기간·공개키 알고리즘·서명 알고리즘이 모두 출력됨
- 만료 여부·자체 서명·약한 키·취약 서명 알고리즘에 대한 자동 판정이 완료됨
- (CA 번들 제공 시) 체인 검증 결과(OK 또는 오류 코드)가 출력됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| `unable to load certificate` | 파일 형식 불일치. DER이면 `-inform DER` 추가 |
| SAN 필드 없음 | 구형 인증서. CN만 사용. 최신 브라우저는 SAN 없는 인증서 거부 가능 |
| 체인 검증 `unable to get local issuer certificate` | 중간 CA 인증서 누락. 서버에서 전체 체인 파일 수집 필요 |
| 원격 인증서 수집 실패 | 방화벽 또는 SNI 문제. `-servername` 플래그와 포트 확인 |

## 참고

- 전체 체인(중간 CA 포함) 수집: `openssl s_client -connect host:443 -showcerts`
- 인증서 핀닝(Certificate Pinning) 검증이 필요하면 공개키 해시 추출: `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`
- CT(Certificate Transparency) 로그 검색: https://crt.sh/?q=example.com
