---
name: dependency-audit
description: Dependency vulnerability audit across Node.js, Python, and Go ecosystems
license: MIT
metadata:
  category: vuln-analysis
  locale: ko
  phase: vuln-analysis
---

## 이 스킬이 하는 일

프로젝트 유형(Node.js, Python, Go, 컨테이너)을 자동으로 감지하고 적절한 감사 도구(`npm audit`, `pip-audit`, `trivy`)를 실행합니다. 발견된 취약점을 심각도별로 집계하고, 수정 가능한 버전을 포함한 권고 사항을 출력합니다.

## 언제 사용하나

- 코드 리뷰 또는 배포 전 의존성 취약점을 점검할 때
- CI/CD 파이프라인에서 자동화된 의존성 보안 게이트를 구성할 때
- 오래된 프로젝트의 누적된 취약점을 한 번에 감사할 때
- 컨테이너 이미지 또는 파일시스템의 취약점을 스캔할 때

## 사전 조건

- Node.js 프로젝트: `npm` 설치 (Node.js에 포함)
- Python 프로젝트: `pip-audit` 설치:
  ```bash
  pip install pip-audit
  ```
- 컨테이너/범용: `trivy` 설치:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y wget apt-transport-https gnupg
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install -y trivy
  ```
- 환경 변수 `SECSKILL_PROJECT_PATH`: 프로젝트 루트 경로

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_PROJECT_PATH` | 필수 | 감사할 프로젝트 루트 경로 |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 저장 디렉터리 (기본: `./output`) |
| `SECSKILL_MIN_SEVERITY` | 선택 | 최소 심각도 필터 `low/medium/high/critical` (기본: `medium`) |
| `SECSKILL_TRIVY_TARGET` | 선택 | trivy 스캔 대상 (경로 또는 이미지명, 기본: 프로젝트 경로) |

## 워크플로우

### 1단계: 환경 준비 및 프로젝트 유형 감지

```bash
export PROJECT="${SECSKILL_PROJECT_PATH:?SECSKILL_PROJECT_PATH 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export MIN_SEV="${SECSKILL_MIN_SEVERITY:-medium}"
mkdir -p "$OUTDIR"

if [ ! -d "$PROJECT" ]; then
  echo "[-] 경로를 찾을 수 없습니다: $PROJECT"
  exit 1
fi

echo "[*] 프로젝트 유형 감지 중: $PROJECT"

HAS_NPM=false
HAS_PYTHON=false
HAS_GO=false

[ -f "$PROJECT/package.json" ] && HAS_NPM=true && echo "[+] Node.js 프로젝트 감지 (package.json)"
[ -f "$PROJECT/package-lock.json" ] || [ -f "$PROJECT/yarn.lock" ] && HAS_NPM=true
[ -f "$PROJECT/requirements.txt" ] || [ -f "$PROJECT/Pipfile" ] || [ -f "$PROJECT/pyproject.toml" ] && HAS_PYTHON=true && echo "[+] Python 프로젝트 감지"
[ -f "$PROJECT/go.mod" ] && HAS_GO=true && echo "[+] Go 프로젝트 감지 (go.mod)"

SUMMARY_FILE="$OUTDIR/dependency_audit_summary.txt"
echo "의존성 감사 보고서" > "$SUMMARY_FILE"
echo "경로: $PROJECT" >> "$SUMMARY_FILE"
echo "일시: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
```

### 2단계: npm audit (Node.js)

```bash
if [ "$HAS_NPM" = "true" ]; then
  echo ""
  echo "[*] npm audit 실행 중..."
  cd "$PROJECT"

  # package-lock.json 없으면 생성
  if [ ! -f "package-lock.json" ] && [ ! -f "yarn.lock" ]; then
    echo "[*] package-lock.json 생성 중..."
    npm install --package-lock-only --silent 2>/dev/null
  fi

  npm audit \
    --audit-level="$MIN_SEV" \
    --json 2>/dev/null \
    > "$OUTDIR/npm_audit.json"

  NPM_TOTAL=$(jq '.metadata.vulnerabilities | (.critical + .high + .moderate + .low)' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  NPM_CRITICAL=$(jq '.metadata.vulnerabilities.critical' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  NPM_HIGH=$(jq '.metadata.vulnerabilities.high' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")

  echo "[+] npm audit 완료: 총 $NPM_TOTAL 건 (critical: $NPM_CRITICAL, high: $NPM_HIGH)"

  cat >> "$SUMMARY_FILE" << EOF
[ Node.js (npm audit) ]
총 취약점: $NPM_TOTAL
  Critical : $NPM_CRITICAL
  High     : $NPM_HIGH
  Moderate : $(jq '.metadata.vulnerabilities.moderate' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")
  Low      : $(jq '.metadata.vulnerabilities.low' "$OUTDIR/npm_audit.json" 2>/dev/null || echo "0")

수정 가능 항목:
$(jq -r '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") | "  - \(.key): \(.value.severity) -> \(.value.fixAvailable // "수동 수정 필요")"' "$OUTDIR/npm_audit.json" 2>/dev/null | head -10)

EOF
  cd - > /dev/null
fi
```

### 3단계: pip-audit (Python)

```bash
if [ "$HAS_PYTHON" = "true" ]; then
  echo ""
  echo "[*] pip-audit 실행 중..."

  PIP_AUDIT_ARGS=""
  if [ -f "$PROJECT/requirements.txt" ]; then
    PIP_AUDIT_ARGS="-r $PROJECT/requirements.txt"
  fi

  pip-audit \
    $PIP_AUDIT_ARGS \
    --format=json \
    --output="$OUTDIR/pip_audit.json" \
    2>/dev/null

  PIP_TOTAL=$(jq '[.[].vulns[]] | length' "$OUTDIR/pip_audit.json" 2>/dev/null || echo "0")
  echo "[+] pip-audit 완료: $PIP_TOTAL 건 발견"

  cat >> "$SUMMARY_FILE" << EOF
[ Python (pip-audit) ]
총 취약점: $PIP_TOTAL

발견 항목:
$(jq -r '.[] | select(.vulns | length > 0) | "  - \(.name) \(.version): \(.vulns | length)건 (\(.vulns[0].id // "?"))"' "$OUTDIR/pip_audit.json" 2>/dev/null | head -10)

EOF
fi
```

### 4단계: trivy (Go 및 범용)

```bash
if [ "$HAS_GO" = "true" ] || [ -f "$PROJECT/Dockerfile" ] || [ -f "$PROJECT/go.mod" ]; then
  echo ""
  echo "[*] trivy 스캔 실행 중..."
  TRIVY_TARGET="${SECSKILL_TRIVY_TARGET:-$PROJECT}"

  if command -v trivy >/dev/null 2>&1; then
    trivy fs \
      --severity "$(echo $MIN_SEV | tr '[:lower:]' '[:upper:]'),HIGH,CRITICAL" \
      --format json \
      --output "$OUTDIR/trivy_audit.json" \
      --quiet \
      "$TRIVY_TARGET" 2>/dev/null

    TRIVY_TOTAL=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$OUTDIR/trivy_audit.json" 2>/dev/null || echo "0")
    echo "[+] trivy 스캔 완료: $TRIVY_TOTAL 건 발견"

    cat >> "$SUMMARY_FILE" << EOF
[ trivy (파일시스템 스캔) ]
총 취약점: $TRIVY_TOTAL

Critical/High 항목:
$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "  - [\(.Severity)] \(.VulnerabilityID): \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion // "수정 버전 없음")"' "$OUTDIR/trivy_audit.json" 2>/dev/null | head -15)

EOF
  else
    echo "[-] trivy 미설치. Go 감사를 건너뜁니다."
  fi
fi
```

### 5단계: 전체 요약 출력

```bash
echo ""
echo "===== 의존성 감사 결과 요약 ====="
cat "$SUMMARY_FILE"
echo "=================================="
echo "상세 결과:"
[ -f "$OUTDIR/npm_audit.json" ] && echo "  npm   : $OUTDIR/npm_audit.json"
[ -f "$OUTDIR/pip_audit.json" ] && echo "  pip   : $OUTDIR/pip_audit.json"
[ -f "$OUTDIR/trivy_audit.json" ] && echo "  trivy : $OUTDIR/trivy_audit.json"
echo "요약    : $SUMMARY_FILE"
```

## 완료 조건

- 감지된 프로젝트 유형에 대해 적절한 감사 도구가 실행된다
- 심각도별 취약점 수가 집계된다
- 요약 파일이 생성된다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `npm audit` 실패 | package-lock.json 없음 | `npm install` 먼저 실행 |
| pip-audit 오류 | 가상환경 미활성화 | `source venv/bin/activate` 후 재실행 |
| trivy DB 다운로드 느림 | 네트워크 속도 문제 | `trivy image --download-db-only` 사전 실행 |
| 모든 도구 미감지 | 지원하지 않는 프로젝트 구조 | `SECSKILL_TRIVY_TARGET` 로 경로 명시 |

## 참고

- `npm audit fix` 로 자동 수정 가능한 취약점을 일괄 수정할 수 있습니다.
- pip-audit는 `pip install --upgrade <package>` 권고를 포함합니다.
- trivy는 OS 패키지, 언어별 의존성, 컨테이너 이미지를 모두 스캔합니다.
- CI/CD 통합 시 critical 취약점 발견 시 빌드를 중단하는 게이트를 설정하세요.
