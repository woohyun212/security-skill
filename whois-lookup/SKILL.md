---
name: whois-lookup
description: Domain and IP WHOIS lookup to gather registration and ownership information
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

`whois` 명령을 사용해 도메인 또는 IP 주소의 등록 정보를 조회합니다. 등록자/등록기관 정보, 등록일/만료일, 네임서버, IP 대역(CIDR) 등 핵심 정보를 파싱하고 정리하여 보고서 형식으로 출력합니다.

## 언제 사용하나

- 도메인 소유자 및 등록 기관을 확인할 때
- 도메인 만료일을 통해 인수 가능성을 평가할 때
- IP 주소의 소속 ASN 및 조직을 파악할 때
- 관련 IP 대역(CIDR)을 탐색해 추가 공격 표면을 발굴할 때

## 사전 조건

- `whois` 명령 설치:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y whois
  # CentOS/RHEL
  sudo yum install -y whois
  ```
- 환경 변수 `SECSKILL_TARGET`: 조회할 도메인 또는 IP 주소

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET` | 필수 | 조회할 도메인 또는 IP 주소 |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |

## 워크플로우

### 1단계: 환경 준비 및 입력 유형 감지

```bash
export TARGET="${SECSKILL_TARGET:?SECSKILL_TARGET 환경 변수를 설정하세요 (도메인 또는 IP)}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

# IPv4/IPv6 여부 감지
if echo "$TARGET" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  TARGET_TYPE="ipv4"
elif echo "$TARGET" | grep -qE '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'; then
  TARGET_TYPE="ipv6"
else
  TARGET_TYPE="domain"
fi

echo "[*] 대상: $TARGET (유형: $TARGET_TYPE)"
SAFE_NAME=$(echo "$TARGET" | tr '/' '_')
OUTFILE="$OUTDIR/whois_${SAFE_NAME}.txt"
```

### 2단계: WHOIS 원본 조회 및 저장

```bash
echo "[*] WHOIS 조회 중..."
echo "===== WHOIS 원본 데이터: $TARGET =====" > "$OUTFILE"
echo "조회 시각: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"
echo "" >> "$OUTFILE"

whois "$TARGET" 2>/dev/null >> "$OUTFILE"

if [ $? -ne 0 ] || [ ! -s "$OUTFILE" ]; then
  echo "[-] WHOIS 조회 실패 또는 결과 없음"
  exit 1
fi
echo "[+] 원본 WHOIS 데이터 저장 완료: $OUTFILE"
```

### 3단계: 도메인 핵심 필드 파싱

```bash
if [ "$TARGET_TYPE" = "domain" ]; then
  echo ""
  echo "===== 도메인 WHOIS 요약 ====="

  REGISTRAR=$(grep -iE "Registrar:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  CREATED=$(grep -iE "Creation Date:|Created:|Registered:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  EXPIRES=$(grep -iE "Expiry Date:|Expiration Date:|Expires:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  UPDATED=$(grep -iE "Updated Date:|Last Modified:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  STATUS=$(grep -iE "Domain Status:" "$OUTFILE" | head -3 | cut -d':' -f2- | xargs | tr '\n' ', ')
  NS=$(grep -iE "Name Server:" "$OUTFILE" | cut -d':' -f2- | xargs | tr ' ' '\n' | sort -u | tr '\n' ' ')
  REGISTRANT=$(grep -iE "Registrant Organization:|Registrant Name:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  REGISTRANT_EMAIL=$(grep -iE "Registrant Email:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)

  echo "등록기관    : ${REGISTRAR:-(정보 없음)}"
  echo "등록자      : ${REGISTRANT:-(개인정보 보호 적용됨)}"
  echo "등록자 이메일: ${REGISTRANT_EMAIL:-(비공개)}"
  echo "등록일      : ${CREATED:-(정보 없음)}"
  echo "만료일      : ${EXPIRES:-(정보 없음)}"
  echo "최종 수정일 : ${UPDATED:-(정보 없음)}"
  echo "도메인 상태 : ${STATUS:-(정보 없음)}"
  echo "네임서버    : ${NS:-(정보 없음)}"
  echo "==============================="
fi
```

### 4단계: IP 주소 핵심 필드 파싱

```bash
if [ "$TARGET_TYPE" = "ipv4" ] || [ "$TARGET_TYPE" = "ipv6" ]; then
  echo ""
  echo "===== IP WHOIS 요약 ====="

  NETRANGE=$(grep -iE "NetRange:|inetnum:|CIDR:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  CIDR=$(grep -iE "CIDR:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  NETNAME=$(grep -iE "NetName:|netname:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ORGNAME=$(grep -iE "OrgName:|org-name:|owner:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  COUNTRY=$(grep -iE "Country:|country:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ASN=$(grep -iE "OriginAS:|origin:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ABUSE=$(grep -iE "OrgAbuseEmail:|abuse-mailbox:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)

  echo "IP 대역     : ${NETRANGE:-(정보 없음)}"
  echo "CIDR        : ${CIDR:-(정보 없음)}"
  echo "네트워크명  : ${NETNAME:-(정보 없음)}"
  echo "조직        : ${ORGNAME:-(정보 없음)}"
  echo "국가        : ${COUNTRY:-(정보 없음)}"
  echo "ASN         : ${ASN:-(정보 없음)}"
  echo "신고 이메일 : ${ABUSE:-(정보 없음)}"
  echo "========================="
fi
```

### 5단계: 관련 IP 대역 추출 (도메인인 경우)

```bash
if [ "$TARGET_TYPE" = "domain" ]; then
  echo ""
  echo "[*] 도메인 A 레코드로부터 IP 대역 조회..."
  IP=$(dig "$TARGET" A +short 2>/dev/null | head -1)
  if [ -n "$IP" ]; then
    echo "[*] 확인된 IP: $IP - WHOIS 조회 중..."
    whois "$IP" 2>/dev/null \
      | grep -iE "NetRange:|inetnum:|CIDR:|OrgName:|org-name:" \
      | head -10 \
      | tee -a "$OUTFILE"
  else
    echo "[-] A 레코드 없음"
  fi
fi
```

## 완료 조건

- WHOIS 원본 데이터가 파일에 저장된다
- 핵심 필드(등록기관, 날짜, 네임서버 또는 IP 대역, 조직)가 파싱되어 출력된다
- 결과 파일 경로가 표시된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `whois: command not found` | 미설치 | `apt-get install whois` 실행 |
| 결과가 비어있음 | WHOIS 서버 응답 없음 | 수동으로 `whois -h whois.iana.org $TARGET` 시도 |
| 개인정보 보호로 정보 없음 | GDPR/Privacy Shield 적용 | 정상 상황. 다른 정찰 수단 활용 |
| 레이트 리밋 오류 | 너무 많은 요청 | 잠시 대기 후 재시도 |

## 참고

- 만료일이 가까운 도메인은 도메인 인수(Domain Takeover) 가능성을 추가 평가하세요.
- GDPR 이후 많은 도메인의 등록자 정보가 비공개 처리됩니다.
- IP 대역 정보는 추가 스캔 범위 정의에 활용할 수 있습니다.
- 결과는 `port-scan` 스킬과 연계하여 사용할 수 있습니다.
