---
name: dns-recon
description: DNS record reconnaissance and zone transfer attempts using dig, host, and nslookup
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

dig, host, nslookup을 사용해 대상 도메인의 DNS 레코드를 전수 조회합니다. A/AAAA/MX/NS/TXT/CNAME 레코드를 열거하고, 존 전송(Zone Transfer) 취약점을 점검하며, DNSSEC 설정 여부를 확인합니다.

## 언제 사용하나

- 도메인의 인프라 구조(메일 서버, 네임서버, IP 대역)를 파악할 때
- 잘못 설정된 DNS 존 전송 취약점을 탐지할 때
- SPF/DKIM/DMARC 설정 상태를 감사할 때
- 서브도메인 인계(Subdomain Takeover) 후보를 찾을 때

## 사전 조건

- `dnsutils` 패키지 설치 (dig, host, nslookup 포함):
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y dnsutils
  # CentOS/RHEL
  sudo yum install -y bind-utils
  ```
- 환경 변수 `SECSKILL_TARGET_DOMAIN`: 대상 도메인

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET_DOMAIN` | 필수 | 조회할 도메인 (예: `example.com`) |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_DNS_RESOLVER` | 선택 | 사용할 DNS 리졸버 IP (기본: 시스템 기본값) |

## 워크플로우

### 1단계: 환경 준비

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?SECSKILL_TARGET_DOMAIN 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export RESOLVER="${SECSKILL_DNS_RESOLVER:-}"
mkdir -p "$OUTDIR"
RESOLVER_OPT=""
[ -n "$RESOLVER" ] && RESOLVER_OPT="@${RESOLVER}"
echo "[*] DNS 정찰 시작: $TARGET"
```

### 2단계: 기본 레코드 조회 (A, AAAA, MX, NS, TXT, CNAME)

```bash
OUTFILE="$OUTDIR/dns_records_${TARGET}.txt"
echo "===== DNS 레코드 조회: $TARGET =====" > "$OUTFILE"
echo "조회 시각: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"
echo "" >> "$OUTFILE"

for RTYPE in A AAAA MX NS TXT CNAME SOA; do
  echo "--- ${RTYPE} 레코드 ---" | tee -a "$OUTFILE"
  dig $RESOLVER_OPT "$TARGET" "$RTYPE" +noall +answer 2>/dev/null \
    | tee -a "$OUTFILE"
  echo "" >> "$OUTFILE"
done

echo "[+] 기본 레코드 조회 완료"
```

### 3단계: 이메일 보안 레코드 확인 (SPF, DKIM, DMARC)

```bash
echo "--- 이메일 보안 레코드 ---" | tee -a "$OUTFILE"

echo "[SPF]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "$TARGET" TXT +short 2>/dev/null \
  | grep -i "v=spf" | tee -a "$OUTFILE"

echo "[DMARC]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "_dmarc.${TARGET}" TXT +short 2>/dev/null \
  | tee -a "$OUTFILE"

echo "[DKIM - default selector]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "default._domainkey.${TARGET}" TXT +short 2>/dev/null \
  | tee -a "$OUTFILE"

echo "[+] 이메일 보안 레코드 확인 완료"
```

### 4단계: 네임서버 목록 추출 후 존 전송 시도

```bash
echo "" >> "$OUTFILE"
echo "--- 존 전송(Zone Transfer) 시도 ---" | tee -a "$OUTFILE"

NS_LIST=$(dig $RESOLVER_OPT "$TARGET" NS +short 2>/dev/null | sed 's/\.$//')
if [ -z "$NS_LIST" ]; then
  echo "[-] 네임서버를 찾을 수 없습니다." | tee -a "$OUTFILE"
else
  echo "$NS_LIST" | while read -r NS; do
    echo "[*] 시도: $NS 에서 존 전송 요청..." | tee -a "$OUTFILE"
    RESULT=$(dig @"$NS" "$TARGET" AXFR 2>/dev/null)
    if echo "$RESULT" | grep -q "Transfer failed\|connection refused\|REFUSED\|timed out"; then
      echo "[-] $NS: 존 전송 거부됨 (정상)" | tee -a "$OUTFILE"
    elif echo "$RESULT" | grep -q "XFR size"; then
      echo "[!] $NS: 존 전송 성공! 취약점 발견" | tee -a "$OUTFILE"
      echo "$RESULT" >> "$OUTFILE"
    else
      echo "[-] $NS: 응답 없음 또는 알 수 없는 결과" | tee -a "$OUTFILE"
    fi
  done
fi
```

### 5단계: DNSSEC 확인

```bash
echo "" >> "$OUTFILE"
echo "--- DNSSEC 확인 ---" | tee -a "$OUTFILE"

DNSKEY=$(dig $RESOLVER_OPT "$TARGET" DNSKEY +short 2>/dev/null)
DS=$(dig $RESOLVER_OPT "$TARGET" DS +short 2>/dev/null)

if [ -n "$DNSKEY" ] || [ -n "$DS" ]; then
  echo "[+] DNSSEC 활성화됨" | tee -a "$OUTFILE"
  echo "DNSKEY: $DNSKEY" >> "$OUTFILE"
  echo "DS: $DS" >> "$OUTFILE"
else
  echo "[-] DNSSEC 미설정" | tee -a "$OUTFILE"
fi

echo "[+] DNS 정찰 완료: $OUTFILE"
```

### 6단계: 결과 요약

```bash
echo ""
echo "===== DNS 정찰 결과 요약 ====="
echo "대상     : $TARGET"
echo "A 레코드 : $(dig $RESOLVER_OPT $TARGET A +short 2>/dev/null | tr '\n' ' ')"
echo "MX 레코드: $(dig $RESOLVER_OPT $TARGET MX +short 2>/dev/null | tr '\n' ' ')"
echo "NS 레코드: $(dig $RESOLVER_OPT $TARGET NS +short 2>/dev/null | tr '\n' ' ')"
echo "결과 파일: $OUTFILE"
echo "=============================="
```

## 완료 조건

- 모든 레코드 타입에 대한 조회가 완료된다
- 존 전송 시도 결과가 기록된다 (성공/실패 무관)
- DNSSEC 상태가 확인된다
- 결과 파일이 생성된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `dig: command not found` | dnsutils 미설치 | `apt-get install dnsutils` 실행 |
| 모든 쿼리 타임아웃 | 방화벽 또는 DNS 차단 | 다른 리졸버 지정 (`SECSKILL_DNS_RESOLVER=8.8.8.8`) |
| 존 전송 결과 비어있음 | 정상적으로 거부됨 | 다른 공격 벡터 탐색 |
| NXDOMAIN 응답 | 도메인 오타 또는 미존재 | 도메인 철자 확인 |

## 참고

- 존 전송 취약점이 발견되면 보고서에 즉시 기재하세요. 이는 고위험 취약점입니다.
- TXT 레코드에는 내부 인프라 힌트, 서비스 인증 토큰 등이 포함될 수 있습니다.
- `host -l` 명령도 존 전송에 사용할 수 있습니다: `host -l $TARGET $NAMESERVER`
- SPF `~all` 또는 `+all` 설정은 스푸핑에 취약하므로 별도 보고하세요.
