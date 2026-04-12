---
name: nuclei-scan
description: Nuclei template-based vulnerability scanning with severity filtering and structured output
license: MIT
metadata:
  category: vuln-analysis
  locale: ko
  phase: vuln-analysis
---

## 이 스킬이 하는 일

ProjectDiscovery의 Nuclei를 사용해 대상 URL 또는 호스트 목록에 대해 템플릿 기반 취약점 스캔을 수행합니다. 템플릿을 최신 상태로 업데이트하고, 심각도 필터를 적용해 스캔한 후 JSON 출력을 파싱하여 발견 사항을 요약합니다.

## 언제 사용하나

- 알려진 취약점 패턴(CVE, 기본 자격증명, 설정 오류)을 자동으로 탐지할 때
- 다수의 호스트를 동시에 빠르게 스캔할 때
- `subdomain-enum`이나 `port-scan` 결과를 취약점 분석으로 연결할 때
- CI/CD 파이프라인에서 자동화된 보안 검증을 수행할 때

## 사전 조건

- Nuclei 설치:
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- Go 1.21 이상 설치
- 환경 변수 `SECSKILL_TARGET` 또는 `SECSKILL_TARGET_LIST`: 스캔 대상

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET` | 둘 중 하나 | 단일 대상 URL 또는 호스트 |
| `SECSKILL_TARGET_LIST` | 둘 중 하나 | 대상 목록 파일 경로 |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_SEVERITY` | 선택 | 필터링할 심각도 (기본: `medium,high,critical`) |
| `SECSKILL_TEMPLATES` | 선택 | 사용할 템플릿 경로 또는 태그 (기본: 전체) |
| `SECSKILL_RATE_LIMIT` | 선택 | 초당 최대 요청 수 (기본: `150`) |

## 워크플로우

### 1단계: 환경 준비 및 입력 검증

```bash
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SEVERITY="${SECSKILL_SEVERITY:-medium,high,critical}"
export RATE="${SECSKILL_RATE_LIMIT:-150}"
export TEMPLATES="${SECSKILL_TEMPLATES:-}"
mkdir -p "$OUTDIR"

# 대상 설정
if [ -n "${SECSKILL_TARGET:-}" ]; then
  TARGET_OPT="-u $SECSKILL_TARGET"
  SAFE_NAME=$(echo "$SECSKILL_TARGET" | tr '/:.' '___')
elif [ -n "${SECSKILL_TARGET_LIST:-}" ]; then
  if [ ! -f "$SECSKILL_TARGET_LIST" ]; then
    echo "[-] 대상 목록 파일을 찾을 수 없습니다: $SECSKILL_TARGET_LIST"
    exit 1
  fi
  TARGET_OPT="-l $SECSKILL_TARGET_LIST"
  SAFE_NAME="list_$(basename "$SECSKILL_TARGET_LIST" .txt)"
else
  echo "[-] SECSKILL_TARGET 또는 SECSKILL_TARGET_LIST 중 하나를 설정하세요"
  exit 1
fi

echo "[*] Nuclei 스캔 준비 완료"
echo "[*] 심각도 필터: $SEVERITY"
echo "[*] 요청 속도  : $RATE req/s"
```

### 2단계: Nuclei 템플릿 업데이트

```bash
echo "[*] 템플릿 업데이트 중..."
nuclei -update-templates 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[+] 템플릿 업데이트 완료"
else
  echo "[-] 템플릿 업데이트 실패 (기존 템플릿으로 진행)"
fi
```

### 3단계: Nuclei 스캔 실행

```bash
echo "[*] Nuclei 스캔 시작..."
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
JSON_OUT="$OUTDIR/nuclei_${SAFE_NAME}_${TIMESTAMP}.json"
TXT_OUT="$OUTDIR/nuclei_${SAFE_NAME}_${TIMESTAMP}.txt"

# 템플릿 옵션 구성
TMPL_OPT=""
if [ -n "$TEMPLATES" ]; then
  TMPL_OPT="-t $TEMPLATES"
fi

nuclei \
  $TARGET_OPT \
  -severity "$SEVERITY" \
  $TMPL_OPT \
  -rate-limit "$RATE" \
  -json-export "$JSON_OUT" \
  -output "$TXT_OUT" \
  -stats \
  -silent 2>/dev/null

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 1 ]; then
  echo "[-] Nuclei 실행 오류 (종료 코드: $EXIT_CODE)"
  exit $EXIT_CODE
fi
echo "[+] 스캔 완료"
```

### 4단계: JSON 결과 파싱 및 요약

```bash
echo "[*] 결과 분석 중..."

if [ ! -f "$JSON_OUT" ] || [ ! -s "$JSON_OUT" ]; then
  echo "[+] 발견된 취약점 없음 (지정한 심각도 기준)"
  echo "스캔 완료. 취약점 없음." > "$TXT_OUT"
else
  TOTAL=$(wc -l < "$JSON_OUT")
  echo "[!] 총 발견 수: $TOTAL 건"

  echo ""
  echo "===== 심각도별 요약 ====="
  for SEV in critical high medium; do
    COUNT=$(grep -c "\"severity\":\"${SEV}\"" "$JSON_OUT" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && echo "  $SEV: $COUNT 건"
  done
  echo "========================="
fi
```

### 5단계: 고위험 발견 사항 상세 출력

```bash
if [ -f "$JSON_OUT" ] && [ -s "$JSON_OUT" ]; then
  echo ""
  echo "===== Critical/High 발견 사항 ====="
  grep -E '"severity":"(critical|high)"' "$JSON_OUT" 2>/dev/null \
    | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        item = json.loads(line.strip())
        info = item.get('info', {})
        print(f\"  [{info.get('severity','?').upper()}] {info.get('name','?')}\")
        print(f\"    템플릿  : {item.get('template-id','?')}\")
        print(f\"    대상    : {item.get('host','?')}\")
        print(f\"    매칭 URL: {item.get('matched-at','?')}\")
        print()
    except:
        pass
" 2>/dev/null || echo "  (파싱 중 오류 발생 - 원본 JSON 파일 확인)"
  echo "==================================="
fi
```

### 6단계: 결과 요약

```bash
echo ""
echo "===== Nuclei 스캔 결과 요약 ====="
echo "심각도 필터  : $SEVERITY"
echo "JSON 결과    : $JSON_OUT"
echo "텍스트 결과  : $TXT_OUT"
echo "=================================="
```

## 완료 조건

- Nuclei 스캔이 오류 없이 완료된다
- JSON 결과 파일이 생성된다 (발견 없어도 빈 파일 생성)
- 심각도별 요약이 출력된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `nuclei: command not found` | 미설치 또는 PATH 문제 | `$GOPATH/bin` 이 PATH에 있는지 확인 |
| 템플릿 업데이트 실패 | 네트워크 문제 | 기존 템플릿으로 진행, 수동 업데이트 시도 |
| 스캔 속도 느림 | 레이트 리밋 낮음 | `SECSKILL_RATE_LIMIT=500` 으로 증가 |
| 너무 많은 오탐 | 템플릿 범위 넓음 | `SECSKILL_TEMPLATES` 로 특정 태그 지정 |
| 연결 오류 | 대상 오프라인 | 대상 연결 상태 확인 |

## 참고

- 반드시 **사전 승인된 대상**에만 사용하세요. Nuclei는 실제 취약점을 확인하는 프로브를 전송합니다.
- `-severity critical,high` 로 시작해 중요한 취약점을 먼저 파악하는 것을 권장합니다.
- `-tags cve,exposure,misconfig` 처럼 태그로 스캔 범위를 좁힐 수 있습니다.
- JSON 출력은 `cve-lookup` 스킬과 연동해 CVSS 점수를 보완할 수 있습니다.
- 템플릿 디렉터리는 기본적으로 `~/.local/nuclei-templates/` 에 저장됩니다.
