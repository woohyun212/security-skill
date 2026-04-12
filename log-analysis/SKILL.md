---
name: log-analysis
description: Security log analysis and anomaly detection for access, auth, and syslog files
license: MIT
metadata:
  category: incident-response
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

보안 로그 파일을 분석하여 이상 징후를 탐지합니다. 웹 액세스 로그에서 상위 IP/경로/상태코드/User-Agent를 추출하고, 브루트포스 패턴(다중 401), 스캐닝(순차 경로 열거)을 탐지합니다. 인증 로그에서 실패한 로그인 패턴을, syslog에서 에러/경고 패턴을 추출하여 타임라인과 함께 요약 보고서를 출력합니다.

## 언제 사용하나요

- 웹 서버 침해 의심 시 액세스 로그를 분석할 때
- SSH 브루트포스 공격 여부를 확인할 때
- 인시던트 대응 중 공격 타임라인을 재구성할 때
- 정기적인 보안 모니터링 및 이상 탐지를 자동화할 때

## 사전 요구 사항

- `grep`, `awk`, `sort`, `uniq` (대부분의 Linux에 기본 설치)
- `python3` (고급 분석 및 보고서 생성)
- 분석 대상 로그 파일에 대한 읽기 권한

## 입력

| 항목 | 설명 | 예시 |
|------|------|------|
| `LOG_FILE` | 분석할 로그 파일 경로 | `/var/log/nginx/access.log` |
| `LOG_TYPE` | 로그 유형: `access` / `auth` / `syslog` | `access` |
| `TOP_N` | 상위 N개 항목 표시 (기본값: 20) | `20` |

## 워크플로

### 1단계: 로그 파일 및 유형 확인

```bash
LOG_FILE="${1:-}"
LOG_TYPE="${2:-auto}"
TOP_N="${3:-20}"

if [ -z "$LOG_FILE" ]; then
    read -rp "로그 파일 경로를 입력하세요: " LOG_FILE
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "[!] 파일을 찾을 수 없습니다: $LOG_FILE"
    exit 1
fi

# 로그 유형 자동 감지
if [ "$LOG_TYPE" = "auto" ]; then
    filename=$(basename "$LOG_FILE")
    case "$filename" in
        access*|nginx*|apache*|httpd*) LOG_TYPE="access" ;;
        auth*|secure*|sshd*) LOG_TYPE="auth" ;;
        syslog*|messages*|system*) LOG_TYPE="syslog" ;;
        *) LOG_TYPE="access" ; echo "[*] 로그 유형 자동 감지 실패, access 로그로 가정합니다." ;;
    esac
fi

TOTAL_LINES=$(wc -l < "$LOG_FILE")
FILE_SIZE=$(du -sh "$LOG_FILE" | cut -f1)
echo "[+] 로그 파일: $LOG_FILE"
echo "    유형: $LOG_TYPE | 라인 수: $TOTAL_LINES | 크기: $FILE_SIZE"
```

### 2단계: 웹 액세스 로그 분석

```bash
if [ "$LOG_TYPE" = "access" ]; then
    echo ""
    echo "=== 웹 액세스 로그 분석 ==="

    # 상위 IP 주소
    echo "[상위 IP 주소] (Top $TOP_N)"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'

    # 상위 요청 경로
    echo ""
    echo "[상위 요청 경로] (Top $TOP_N)"
    awk '{print $7}' "$LOG_FILE" | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'

    # HTTP 상태 코드 분포
    echo ""
    echo "[HTTP 상태 코드 분포]"
    awk '{print $9}' "$LOG_FILE" | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -rn | \
        awk '{printf "  %s: %d회\n", $2, $1}'

    # 상위 User-Agent
    echo ""
    echo "[상위 User-Agent] (Top 10)"
    awk -F'"' '{print $6}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10 | \
        awk '{printf "  %5d회  %s\n", $1, substr($0, index($0,$2))}'
fi
```

### 3단계: 브루트포스 및 스캐닝 패턴 탐지

```bash
if [ "$LOG_TYPE" = "access" ]; then
    echo ""
    echo "=== 이상 징후 탐지 ==="

    python3 - "$LOG_FILE" "$TOP_N" <<'PYEOF'
import sys, re
from collections import defaultdict

log_file = sys.argv[1]
top_n = int(sys.argv[2])

ip_401 = defaultdict(int)
ip_404 = defaultdict(int)
ip_paths = defaultdict(set)
suspicious_ips = set()

# Combined Log Format 파싱
log_pattern = re.compile(r'(\S+) \S+ \S+ \[.*?\] "\S+ (\S+) \S+" (\d{3})')

with open(log_file, 'r', errors='replace') as f:
    for line in f:
        m = log_pattern.match(line)
        if not m:
            continue
        ip, path, status = m.group(1), m.group(2), m.group(3)

        if status == '401':
            ip_401[ip] += 1
        if status == '404':
            ip_404[ip] += 1
            ip_paths[ip].add(path)

# 브루트포스: 동일 IP에서 401이 10회 이상
print("\n[브루트포스 의심 IP] (401 오류 10회 이상)")
bf_found = False
for ip, count in sorted(ip_401.items(), key=lambda x: -x[1]):
    if count >= 10:
        print(f"  [!] {ip}: {count}회 인증 실패")
        suspicious_ips.add(ip)
        bf_found = True
if not bf_found:
    print("  [OK] 브루트포스 패턴 미탐지")

# 스캐닝: 동일 IP에서 404가 20회 이상 (경로 열거)
print("\n[스캐닝 의심 IP] (404 오류 20회 이상)")
scan_found = False
for ip, count in sorted(ip_404.items(), key=lambda x: -x[1]):
    if count >= 20:
        unique_paths = len(ip_paths[ip])
        print(f"  [!] {ip}: {count}회 404, {unique_paths}개 고유 경로")
        suspicious_ips.add(ip)
        scan_found = True
if not scan_found:
    print("  [OK] 스캐닝 패턴 미탐지")

if suspicious_ips:
    print(f"\n[요약] 의심 IP {len(suspicious_ips)}개 발견: {', '.join(suspicious_ips)}")
    # 차단 명령어 제안
    print("\n[차단 명령어 예시 (실행 전 검토 필수)]")
    for ip in list(suspicious_ips)[:5]:
        print(f"  # iptables -A INPUT -s {ip} -j DROP")
PYEOF
fi
```

### 4단계: 인증 로그 분석 (auth/secure)

```bash
if [ "$LOG_TYPE" = "auth" ]; then
    echo ""
    echo "=== 인증 로그 분석 ==="

    # 실패한 SSH 로그인
    echo "[SSH 로그인 실패 상위 IP] (Top $TOP_N)"
    grep -i "failed password\|invalid user\|authentication failure" "$LOG_FILE" | \
        grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        awk '{print $2}' | sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'

    echo ""
    echo "[시도된 사용자 계정] (Top $TOP_N)"
    grep -i "invalid user\|failed password for" "$LOG_FILE" | \
        grep -oE 'for [a-zA-Z0-9._-]+' | awk '{print $2}' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'

    echo ""
    echo "[성공한 로그인]"
    grep -i "accepted password\|accepted publickey" "$LOG_FILE" | \
        grep -oE 'for [a-zA-Z0-9._-]+ from [0-9.]+' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %4d회  %s\n", $1, substr($0, index($0,$2))}'

    FAIL_COUNT=$(grep -ci "failed password\|invalid user" "$LOG_FILE" 2>/dev/null || echo 0)
    echo ""
    echo "[요약] 총 인증 실패: $FAIL_COUNT 건"
fi
```

### 5단계: Syslog 분석

```bash
if [ "$LOG_TYPE" = "syslog" ]; then
    echo ""
    echo "=== Syslog 분석 ==="

    echo "[오류/경고 패턴 (Top $TOP_N)]"
    grep -iE "error|warning|critical|alert|emerg|fail" "$LOG_FILE" | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /[Ee]rror|[Ww]arning|[Cc]ritical/) {key=$i; break}; print key}' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'

    echo ""
    echo "[프로세스별 오류 빈도] (Top $TOP_N)"
    grep -iE "error|critical|emerg" "$LOG_FILE" | \
        awk '{print $5}' | sed 's/\[.*\]//' | sed 's/://' | \
        sort | uniq -c | sort -rn | head -"$TOP_N" | \
        awk '{printf "  %6d회  %s\n", $1, $2}'
fi
```

### 6단계: 타임라인 및 보고서 출력

```bash
python3 - "$LOG_FILE" "$LOG_TYPE" <<'PYEOF'
import sys, re
from collections import defaultdict

log_file = sys.argv[1]
log_type = sys.argv[2]

print("\n" + "=" * 60)
print("타임라인 요약")
print("=" * 60)

# 시간대별 요청 수 (시간 단위)
hourly = defaultdict(int)

if log_type == "access":
    time_pattern = re.compile(r'\[(\d{2}/\w+/\d{4}):(\d{2})')
elif log_type in ("auth", "syslog"):
    time_pattern = re.compile(r'(\w+ \d+ (\d{2}):\d{2}:\d{2})')

with open(log_file, 'r', errors='replace') as f:
    for line in f:
        m = time_pattern.search(line)
        if m:
            if log_type == "access":
                hour = m.group(2)
                date = m.group(1).split(':')[0]
                hourly[f"{date} {hour}:00"] += 1
            else:
                hour = m.group(2)
                hourly[f"{hour}:00"] += 1

print("\n[시간대별 요청/이벤트 수]")
peak = max(hourly.values()) if hourly else 1
for time_key in sorted(hourly.keys())[-24:]:
    count = hourly[time_key]
    bar = '#' * int(count / peak * 30)
    print(f"  {time_key}  {bar:<30} {count}")

print("\n[+] 분석 완료")
PYEOF
```

## 완료 조건

- 로그 유형에 맞는 분석 섹션이 모두 출력됨
- 이상 징후(브루트포스/스캐닝/실패 패턴)가 탐지 또는 미탐지로 명시됨
- 시간대별 타임라인이 시각화됨
- 의심 IP에 대한 차단 명령어 예시가 제시됨 (해당 시)

## 실패 모드

| 문제 | 원인 | 해결책 |
|------|------|--------|
| 권한 거부 | 로그 파일 읽기 권한 없음 | `sudo` 사용 또는 권한 확인 |
| 빈 분석 결과 | 로그 형식 불일치 | 로그 형식 확인 후 `awk` 패턴 조정 |
| python3 미설치 | 파이썬 부재 | `sudo apt install python3` |
| 대용량 파일 느림 | 1GB 이상 로그 | `tail -n 100000` 로 최근 로그만 추출 |

## 참고 사항

- 분석 결과는 참고용이며, 의심 IP 차단 전 반드시 정상 트래픽 여부를 확인하세요.
- 로그 로테이션으로 분산된 파일은 `zcat *.gz | python3 ...` 형태로 연계 가능합니다.
- 탐지된 의심 IP는 `ioc-extract` 스킬로 추가 IOC 확보 후 `malware-hash` 연계 분석을 권장합니다.
- Nginx/Apache Combined Log Format 기준으로 작성되었습니다. 커스텀 포맷은 `awk` 필드 번호를 조정하세요.
