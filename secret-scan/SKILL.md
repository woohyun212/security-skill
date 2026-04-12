---
name: secret-scan
description: Secret and credential detection in source code and git history using trufflehog or gitleaks
license: MIT
metadata:
  category: vuln-analysis
  locale: ko
  phase: vuln-analysis
---

## 이 스킬이 하는 일

trufflehog 또는 gitleaks를 사용해 소스 코드와 git 히스토리에서 API 키, 비밀번호, 토큰, 개인 키 등의 시크릿을 탐지합니다. 발견된 시크릿을 유형별로 분류하고, 조치 방법을 권고합니다.

## 언제 사용하나

- 코드를 공개 저장소에 배포하기 전 시크릿 누출을 점검할 때
- 보안 감사 시 소스 코드 내 하드코딩된 자격증명을 탐지할 때
- 사고 대응 시 git 히스토리에서 과거 시크릿 노출 여부를 확인할 때
- CI/CD 파이프라인에서 커밋 전 시크릿 누출을 자동 차단할 때

## 사전 조건

- trufflehog 설치 (권장):
  ```bash
  go install github.com/trufflesecurity/trufflehog/v3@latest
  ```
- 또는 gitleaks 설치 (대안):
  ```bash
  # Ubuntu/Debian
  GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4)
  wget -q "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
  ```
- 환경 변수 `SECSKILL_SCAN_PATH`: 스캔할 경로 (git 저장소 또는 디렉터리)

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_SCAN_PATH` | 필수 | 스캔할 경로 (git 저장소 루트 권장) |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_SCAN_TOOL` | 선택 | `trufflehog` 또는 `gitleaks` (기본: 자동 감지) |
| `SECSKILL_SCAN_GIT_HISTORY` | 선택 | `true`로 설정 시 전체 git 히스토리 스캔 (기본: `true`) |

## 워크플로우

### 1단계: 환경 준비 및 도구 감지

```bash
export SCAN_PATH="${SECSKILL_SCAN_PATH:?SECSKILL_SCAN_PATH 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export SCAN_GIT="${SECSKILL_SCAN_GIT_HISTORY:-true}"
mkdir -p "$OUTDIR"

if [ ! -e "$SCAN_PATH" ]; then
  echo "[-] 경로를 찾을 수 없습니다: $SCAN_PATH"
  exit 1
fi

# 도구 자동 감지
if [ -n "${SECSKILL_SCAN_TOOL:-}" ]; then
  TOOL="$SECSKILL_SCAN_TOOL"
elif command -v trufflehog >/dev/null 2>&1; then
  TOOL="trufflehog"
elif command -v gitleaks >/dev/null 2>&1; then
  TOOL="gitleaks"
else
  echo "[-] trufflehog 또는 gitleaks 중 하나를 설치하세요"
  exit 1
fi

echo "[*] 시크릿 스캔 시작"
echo "[*] 스캔 도구: $TOOL"
echo "[*] 대상 경로: $SCAN_PATH"
SAFE_NAME=$(basename "$SCAN_PATH")
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
```

### 2단계: trufflehog - git 히스토리 스캔

```bash
if [ "$TOOL" = "trufflehog" ]; then
  echo "[*] trufflehog git 히스토리 스캔 중..."
  JSON_OUT="$OUTDIR/trufflehog_${SAFE_NAME}_${TIMESTAMP}.json"

  IS_GIT=false
  [ -d "$SCAN_PATH/.git" ] && IS_GIT=true

  if [ "$IS_GIT" = "true" ] && [ "$SCAN_GIT" = "true" ]; then
    trufflehog git \
      "file://$SCAN_PATH" \
      --json \
      --no-update \
      2>/dev/null \
      > "$JSON_OUT"
    echo "[+] git 히스토리 스캔 완료"
  fi

  # 현재 파일 스캔
  echo "[*] 현재 파일 스캔 중..."
  FS_OUT="$OUTDIR/trufflehog_fs_${SAFE_NAME}_${TIMESTAMP}.json"
  trufflehog filesystem \
    "$SCAN_PATH" \
    --json \
    --no-update \
    2>/dev/null \
    > "$FS_OUT"
  echo "[+] 파일시스템 스캔 완료"

  # 결과 병합
  cat "$JSON_OUT" "$FS_OUT" 2>/dev/null \
    | grep -v '^$' \
    > "$OUTDIR/secrets_combined_${SAFE_NAME}.json" || true
  COMBINED="$OUTDIR/secrets_combined_${SAFE_NAME}.json"
fi
```

### 3단계: gitleaks - 스캔 실행 (대안)

```bash
if [ "$TOOL" = "gitleaks" ]; then
  echo "[*] gitleaks 스캔 중..."
  GITLEAKS_OUT="$OUTDIR/gitleaks_${SAFE_NAME}_${TIMESTAMP}.json"

  IS_GIT=false
  [ -d "$SCAN_PATH/.git" ] && IS_GIT=true

  if [ "$IS_GIT" = "true" ]; then
    DETECT_CMD="git -p $SCAN_PATH"
    [ "$SCAN_GIT" != "true" ] && DETECT_CMD="dir $SCAN_PATH"
    gitleaks detect \
      --source="$SCAN_PATH" \
      --report-format=json \
      --report-path="$GITLEAKS_OUT" \
      --no-banner \
      2>/dev/null || true
  else
    gitleaks detect \
      --source="$SCAN_PATH" \
      --no-git \
      --report-format=json \
      --report-path="$GITLEAKS_OUT" \
      --no-banner \
      2>/dev/null || true
  fi

  COMBINED="$GITLEAKS_OUT"
  echo "[+] gitleaks 스캔 완료"
fi
```

### 4단계: 발견 사항 분류 및 요약

```bash
echo "[*] 발견 사항 분류 중..."
SUMMARY_FILE="$OUTDIR/secrets_summary_${SAFE_NAME}.txt"

if [ ! -f "$COMBINED" ] || [ ! -s "$COMBINED" ]; then
  echo "[+] 시크릿 발견 없음" | tee "$SUMMARY_FILE"
else
  TOTAL=$(grep -c '"' "$COMBINED" 2>/dev/null | head -1 || echo "알 수 없음")

  cat > "$SUMMARY_FILE" << 'EOF'
===== 시크릿 스캔 결과 =====
EOF

  if [ "$TOOL" = "trufflehog" ]; then
    FINDING_COUNT=$(wc -l < "$COMBINED")
    echo "총 발견 수: $FINDING_COUNT" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "[ 유형별 분류 ]" >> "$SUMMARY_FILE"
    python3 -c "
import sys, json
from collections import Counter
counts = Counter()
findings = []
with open('$COMBINED') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            det = item.get('DetectorName', item.get('detector_name', '알 수 없음'))
            counts[det] += 1
            findings.append(item)
        except:
            pass
for det, cnt in counts.most_common():
    print(f'  {det}: {cnt}건')
print()
print('[ 발견 상세 (상위 20건) ]')
for item in findings[:20]:
    det = item.get('DetectorName', item.get('detector_name', '?'))
    raw = item.get('Raw', item.get('raw', ''))
    file = item.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')
    if not file:
        file = item.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', '알 수 없음')
    masked = str(raw)[:6] + '***' + str(raw)[-4:] if len(str(raw)) > 10 else '***'
    print(f'  [{det}] 파일: {file}')
    print(f'    값(마스킹): {masked}')
" 2>/dev/null >> "$SUMMARY_FILE" || echo "(파싱 오류 - JSON 파일 직접 확인)" >> "$SUMMARY_FILE"
  fi

  if [ "$TOOL" = "gitleaks" ]; then
    python3 -c "
import sys, json
try:
    with open('$COMBINED') as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]
    from collections import Counter
    counts = Counter(item.get('RuleID','?') for item in data)
    print(f'총 발견 수: {len(data)}')
    print()
    print('[ 유형별 분류 ]')
    for rule, cnt in counts.most_common():
        print(f'  {rule}: {cnt}건')
    print()
    print('[ 발견 상세 (상위 20건) ]')
    for item in data[:20]:
        secret = item.get('Secret','')
        masked = secret[:4] + '***' if len(secret) > 4 else '***'
        print(f'  [{item.get(\"RuleID\",\"?\")}] {item.get(\"File\",\"?\")}:{item.get(\"StartLine\",\"?\")}')
        print(f'    값(마스킹): {masked}')
except Exception as e:
    print(f'파싱 오류: {e}')
" 2>/dev/null >> "$SUMMARY_FILE"
  fi
fi
```

### 5단계: 조치 권고

```bash
cat >> "$SUMMARY_FILE" << 'EOF'

===== 조치 권고 사항 =====
1. 발견된 모든 시크릿을 즉시 무효화(revoke)하고 새 자격증명을 발급하세요.
2. git 히스토리에서 시크릿을 제거하려면 BFG Repo Cleaner 또는 git-filter-repo를 사용하세요.
3. 환경 변수 또는 시크릿 관리 서비스(AWS Secrets Manager, HashiCorp Vault 등)를 사용하세요.
4. pre-commit hook에 gitleaks를 통합해 향후 커밋을 차단하세요:
   gitleaks protect --staged -v
5. .gitignore에 .env, *.pem, *.key, config/secrets.* 를 추가하세요.
===========================
EOF

echo ""
cat "$SUMMARY_FILE"
echo ""
echo "결과 파일: $SUMMARY_FILE"
[ -f "$COMBINED" ] && echo "원본 JSON: $COMBINED"
```

## 완료 조건

- 스캔 도구가 오류 없이 실행된다
- 발견 사항이 유형별로 분류된다
- 조치 권고 사항이 출력된다
- 결과 파일이 생성된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `trufflehog: command not found` | 미설치 또는 PATH 문제 | `$GOPATH/bin` PATH 확인 후 재설치 |
| 대형 저장소에서 느림 | git 히스토리 방대 | `--since-commit HEAD~100` 으로 범위 제한 |
| 오탐 너무 많음 | 기본 규칙 범위 넓음 | gitleaks의 `.gitleaks.toml` 설정으로 규칙 조정 |
| JSON 파싱 오류 | 빈 결과 또는 형식 변경 | 원본 파일 직접 확인 |

## 참고

- 시크릿이 발견되면 git 히스토리 재작성보다 자격증명 즉시 무효화가 우선입니다.
- trufflehog는 시크릿의 유효성을 실시간으로 검증하는 기능(`--only-verified`)을 제공합니다.
- pre-commit 통합: `pip install pre-commit` 후 `.pre-commit-config.yaml` 에 gitleaks 추가.
- GitHub, GitLab 등의 플랫폼은 자체 시크릿 스캔 기능을 내장하고 있습니다. 이를 보완적으로 활성화하세요.
- 발견된 시크릿 값을 로그, 이슈 트래커, 슬랙 등에 그대로 노출하지 마세요. 항상 마스킹 처리하세요.
