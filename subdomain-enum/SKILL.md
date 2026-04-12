---
name: subdomain-enum
description: Subdomain enumeration using subfinder and amass to discover attack surface
license: MIT
metadata:
  category: recon
  locale: ko
  phase: recon
---

## 이 스킬이 하는 일

subfinder와 amass를 사용해 대상 도메인의 서브도메인을 열거합니다. 여러 소스(Certificate Transparency, DNS 브루트포스, 패시브 데이터베이스 등)에서 수집한 결과를 병합·중복 제거한 후, httpx로 살아있는 호스트를 검증합니다.

## 언제 사용하나

- 침투 테스트 초기 정찰 단계에서 공격 표면을 파악할 때
- 버그 바운티 대상의 범위를 정의할 때
- 조직의 노출된 서브도메인 인벤토리를 주기적으로 점검할 때

## 사전 조건

- Go 1.21 이상 설치
- subfinder 설치:
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
- amass 설치 (선택):
  ```bash
  go install -v github.com/owasp-amass/amass/v4/...@master
  ```
- httpx 설치 (라이브 검증용):
  ```bash
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
- 환경 변수 `SECSKILL_TARGET_DOMAIN`: 대상 도메인 (예: `example.com`)
- 환경 변수 `SECSKILL_OUTPUT_DIR`: 결과 저장 디렉터리 (기본: `./output`)

## 입력

| 변수 | 필수 | 설명 |
|------|------|------|
| `SECSKILL_TARGET_DOMAIN` | 필수 | 열거할 루트 도메인 |
| `SECSKILL_OUTPUT_DIR` | 선택 | 결과 파일 저장 경로 (기본: `./output`) |
| `SECSKILL_USE_AMASS` | 선택 | `true`로 설정 시 amass도 실행 (기본: `false`) |

## 워크플로우

### 1단계: 환경 준비

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?SECSKILL_TARGET_DOMAIN 환경 변수를 설정하세요}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"
echo "[*] 대상 도메인: $TARGET"
echo "[*] 출력 디렉터리: $OUTDIR"
```

### 2단계: subfinder 실행

```bash
echo "[*] subfinder 실행 중..."
subfinder -d "$TARGET" \
  -silent \
  -o "$OUTDIR/subfinder_${TARGET}.txt"
echo "[+] subfinder 완료: $(wc -l < "$OUTDIR/subfinder_${TARGET}.txt") 개 결과"
```

### 3단계: amass 실행 (선택)

```bash
if [ "${SECSKILL_USE_AMASS:-false}" = "true" ]; then
  echo "[*] amass 실행 중 (시간이 걸릴 수 있습니다)..."
  amass enum -passive -d "$TARGET" \
    -o "$OUTDIR/amass_${TARGET}.txt"
  echo "[+] amass 완료: $(wc -l < "$OUTDIR/amass_${TARGET}.txt") 개 결과"
else
  echo "[*] amass 건너뜀 (SECSKILL_USE_AMASS=true 로 활성화 가능)"
fi
```

### 4단계: 결과 병합 및 중복 제거

```bash
echo "[*] 결과 병합 중..."
cat "$OUTDIR"/subfinder_*.txt "$OUTDIR"/amass_*.txt 2>/dev/null \
  | sort -u \
  > "$OUTDIR/all_subdomains_${TARGET}.txt"
TOTAL=$(wc -l < "$OUTDIR/all_subdomains_${TARGET}.txt")
echo "[+] 중복 제거 후 총 서브도메인: $TOTAL 개"
```

### 5단계: httpx로 라이브 호스트 검증

```bash
echo "[*] 라이브 호스트 검증 중..."
httpx -l "$OUTDIR/all_subdomains_${TARGET}.txt" \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -o "$OUTDIR/live_subdomains_${TARGET}.txt"
LIVE=$(wc -l < "$OUTDIR/live_subdomains_${TARGET}.txt")
echo "[+] 라이브 호스트: $LIVE 개"
echo "[+] 결과 저장 위치: $OUTDIR/live_subdomains_${TARGET}.txt"
```

### 6단계: 요약 출력

```bash
echo ""
echo "===== 서브도메인 열거 결과 요약 ====="
echo "대상 도메인  : $TARGET"
echo "전체 발견    : $TOTAL 개"
echo "라이브 호스트: $LIVE 개"
echo "결과 파일    : $OUTDIR/"
echo "========================================="
```

## 완료 조건

- `all_subdomains_${TARGET}.txt` 파일이 생성되고 1개 이상의 항목을 포함한다
- `live_subdomains_${TARGET}.txt` 파일이 생성된다
- 각 단계의 종료 코드가 0이다

## 실패 모드

| 증상 | 원인 | 해결 방법 |
|------|------|-----------|
| `subfinder: command not found` | 설치 안 됨 | Go PATH 확인 후 재설치 |
| 결과가 0개 | 잘못된 도메인 또는 네트워크 차단 | 도메인 유효성 확인, DNS 연결 테스트 |
| httpx 타임아웃 | 네트워크 지연 | `-timeout` 플래그로 조정 |
| amass가 오래 걸림 | 액티브 열거 모드 | `-passive` 플래그 사용 또는 비활성화 |

## 참고

- 반드시 **사전 서면 승인**을 받은 도메인에만 사용하세요.
- subfinder의 API 키를 `~/.config/subfinder/provider-config.yaml`에 설정하면 더 많은 결과를 얻을 수 있습니다 (Shodan, Censys, VirusTotal 등).
- amass는 실행 시간이 길 수 있으므로 타임아웃(`-timeout 30`)을 설정하는 것을 권장합니다.
- 결과 파일은 이후 `port-scan`, `nuclei-scan` 스킬의 입력으로 활용할 수 있습니다.
