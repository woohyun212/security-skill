---
name: port-scan
description: Port scanning and service detection with nmap for authorized security assessments
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

nmap을 사용해 대상 호스트의 열린 포트를 탐지하고, 서비스 버전 및 운영체제 정보를 수집합니다. 빠른 상위 포트 스캔부터 상세 서비스 버전 탐지, OS 핑거프린팅까지 단계적으로 수행하며 구조화된 형식으로 결과를 저장합니다.

> **중요**: 이 스킬은 반드시 **명시적인 서면 승인**을 받은 시스템에만 사용해야 합니다. 무단 포트 스캔은 대부분의 국가에서 불법이며, 서비스 약관 위반에 해당합니다.

## 언제 사용하나

- 침투 테스트 범위 내 서비스 인벤토리를 구성할 때
- 불필요하게 노출된 서비스를 탐지할 때
- 특정 서비스의 버전을 확인해 CVE를 매핑할 때
- 네트워크 방어 상태를 주기적으로 감사할 때

## 사전 조건

- nmap 설치:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y nmap
  # CentOS/RHEL
  sudo yum install -y nmap
  ```
- **반드시 대상 시스템에 대한 서면 승인이 있어야 합니다.**
- OS 탐지 및 일부 스캔 기법에는 root/sudo 권한이 필요합니다.
- 환경 변수 `SECSKILL_TARGET`: 대상 IP, IP 대역, 또는 호스트명

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET` | 필수 | 스캔 대상 (IP, CIDR, 호스트명) |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_SCAN_SPEED` | 선택 | nmap 속도 템플릿 T1-T5 (기본: `T3`) |
| `SECSKILL_TOP_PORTS` | 선택 | 빠른 스캔 시 검사할 상위 포트 수 (기본: `1000`) |

## 워크플로우

### 1단계: 승인 확인 및 환경 준비

```bash
export TARGET="${SECSKILL_TARGET:?SECSKILL_TARGET 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SPEED="${SECSKILL_SCAN_SPEED:-T3}"
export TOP_PORTS="${SECSKILL_TOP_PORTS:-1000}"
mkdir -p "$OUTDIR"

echo "================================================================"
echo " 경고: 이 스캔은 반드시 승인된 대상에만 수행해야 합니다."
echo " 무단 스캔은 불법이며 법적 책임이 따릅니다."
echo "================================================================"
echo "[*] 스캔 대상: $TARGET"
echo "[*] 출력 경로: $OUTDIR"

SAFE_NAME=$(echo "$TARGET" | tr '/:' '__')
```

### 2단계: 빠른 상위 포트 스캔

```bash
echo "[*] 1단계: 상위 $TOP_PORTS 포트 빠른 스캔 시작..."
nmap -$SPEED \
  --top-ports "$TOP_PORTS" \
  -oN "$OUTDIR/quick_scan_${SAFE_NAME}.txt" \
  -oX "$OUTDIR/quick_scan_${SAFE_NAME}.xml" \
  "$TARGET" 2>/dev/null

echo "[+] 빠른 스캔 완료"
echo "[*] 발견된 열린 포트:"
grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt" | tee /tmp/open_ports.txt
OPEN_COUNT=$(wc -l < /tmp/open_ports.txt)
echo "[+] 열린 포트 수: $OPEN_COUNT"
```

### 3단계: 상세 서비스 버전 스캔

```bash
# 열린 포트만 추출하여 상세 스캔
OPEN_PORTS=$(grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt" \
  | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
  echo "[-] 열린 포트가 없습니다. 스캔을 종료합니다."
  exit 0
fi

echo "[*] 2단계: 서비스 버전 상세 스캔 (포트: $OPEN_PORTS)..."
nmap -$SPEED \
  -p "$OPEN_PORTS" \
  -sV \
  --version-intensity 7 \
  -sC \
  -oN "$OUTDIR/service_scan_${SAFE_NAME}.txt" \
  -oX "$OUTDIR/service_scan_${SAFE_NAME}.xml" \
  "$TARGET" 2>/dev/null

echo "[+] 서비스 버전 스캔 완료"
```

### 4단계: OS 탐지 (root 권한 필요)

```bash
echo "[*] 3단계: OS 탐지 시도..."
if [ "$(id -u)" -eq 0 ]; then
  nmap -$SPEED \
    -p "$OPEN_PORTS" \
    -O \
    --osscan-guess \
    -oN "$OUTDIR/os_scan_${SAFE_NAME}.txt" \
    "$TARGET" 2>/dev/null

  OS_INFO=$(grep -iE "OS details:|Aggressive OS guesses:" "$OUTDIR/os_scan_${SAFE_NAME}.txt" | head -3)
  echo "[+] OS 탐지 결과:"
  echo "${OS_INFO:-(OS 탐지 실패 - 더 많은 열린 포트가 필요할 수 있음)}"
else
  echo "[-] OS 탐지 건너뜀 (root 권한 필요). sudo 로 재실행하면 사용 가능합니다."
fi
```

### 5단계: UDP 주요 서비스 스캔 (선택, root 필요)

```bash
if [ "$(id -u)" -eq 0 ]; then
  echo "[*] 4단계: UDP 주요 서비스 스캔 (DNS/SNMP/NTP 등)..."
  nmap -$SPEED \
    -sU \
    -p 53,67,68,69,123,161,162,500,514,1900 \
    -oN "$OUTDIR/udp_scan_${SAFE_NAME}.txt" \
    "$TARGET" 2>/dev/null
  echo "[+] UDP 스캔 완료"
else
  echo "[-] UDP 스캔 건너뜀 (root 권한 필요)"
fi
```

### 6단계: 결과 요약

```bash
echo ""
echo "===== 포트 스캔 결과 요약 ====="
echo "대상          : $TARGET"
echo "열린 포트 수  : $OPEN_COUNT"
echo ""
echo "[ 서비스 목록 ]"
grep "^[0-9].*open" "$OUTDIR/service_scan_${SAFE_NAME}.txt" 2>/dev/null \
  || grep "^[0-9].*open" "$OUTDIR/quick_scan_${SAFE_NAME}.txt"
echo ""
echo "결과 파일:"
echo "  - $OUTDIR/quick_scan_${SAFE_NAME}.txt"
echo "  - $OUTDIR/service_scan_${SAFE_NAME}.txt"
echo "  - $OUTDIR/service_scan_${SAFE_NAME}.xml (구조화 데이터)"
echo "================================="
```

## 완료 조건

- 빠른 스캔 및 서비스 버전 스캔 결과 파일이 생성된다
- XML 형식의 구조화된 결과 파일이 저장된다
- 열린 포트 목록과 서비스 정보가 출력된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `nmap: command not found` | 미설치 | `apt-get install nmap` 실행 |
| 모든 포트 필터됨 | 방화벽 또는 IPS 차단 | `-Pn` 플래그 추가, 다른 스캔 기법 시도 |
| 스캔이 매우 느림 | 네트워크 지연 또는 T1/T2 속도 | `SECSKILL_SCAN_SPEED=T4` 로 증가 |
| OS 탐지 실패 | 열린 포트 부족 또는 권한 없음 | sudo 실행, 더 많은 포트 스캔 후 재시도 |
| 연결 거부 | 대상 오프라인 또는 필터 | `-Pn` 으로 ping 건너뛰기 |

## 참고

- **법적 경고**: 무단 포트 스캔은 형사 처벌 대상이 될 수 있습니다. 항상 서면 승인을 받으세요.
- `-T4` 또는 `-T5`는 IDS/IPS 경보를 유발할 가능성이 높습니다. 스텔스 테스트 시 `-T1` 또는 `-T2`를 사용하세요.
- XML 출력은 `nuclei-scan` 스킬 및 취약점 관리 플랫폼과 연동할 수 있습니다.
- NSE 스크립트(`-sC`)는 일부 기본 취약점 점검도 수행합니다 (예: SMB signing, SSL 인증서 정보).
