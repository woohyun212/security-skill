---
name: ioc-extract
description: Extract Indicators of Compromise (IOC) from text, logs, or files
license: MIT
metadata:
  category: incident-response
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

텍스트, 로그 파일, URL에서 침해 지표(IOC)를 자동으로 추출합니다. IP 주소, 도메인, URL, 이메일 주소, 파일 해시(MD5/SHA1/SHA256)를 식별하고, 안전한 공유를 위해 디팡(defang) 처리된 구조화된 IOC 목록을 출력합니다.

## 언제 사용하나요

- 인시던트 대응 중 악성 인프라를 식별할 때
- 위협 인텔리전스 보고서나 이메일에서 IOC를 추출할 때
- 로그 파일을 분석하여 공격자 지표를 수집할 때
- SIEM이나 TIP에 입력할 IOC 목록을 준비할 때

## 사전 요구 사항

- Python 3.6 이상
- (선택) ioc-finder 라이브러리: `pip install ioc-finder`
- 입력 소스: 붙여넣기 텍스트, 로컬 파일 경로, 또는 URL

## 입력

| 항목 | 설명 | 예시 |
|------|------|------|
| `INPUT_SOURCE` | 텍스트 직접 입력, 파일 경로, 또는 URL | `/var/log/apache2/access.log` |
| `OUTPUT_FORMAT` | 출력 형식 (text/json/csv) | `json` |

## 워크플로

### 1단계: 입력 소스 확인 및 텍스트 수집

```bash
# 파일에서 텍스트 읽기
INPUT_FILE="/path/to/log.txt"
if [ -f "$INPUT_FILE" ]; then
    TEXT=$(cat "$INPUT_FILE")
elif echo "$INPUT_FILE" | grep -qE '^https?://'; then
    TEXT=$(curl -sL "$INPUT_FILE")
else
    echo "텍스트를 직접 붙여넣고 Ctrl+D로 종료하세요:"
    TEXT=$(cat)
fi
echo "$TEXT" > /tmp/ioc_input.txt
echo "[+] 입력 수집 완료: $(wc -c < /tmp/ioc_input.txt) bytes"
```

### 2단계: ioc-finder로 IOC 추출 (권장)

```bash
# ioc-finder 설치 확인 및 사용
if python3 -c "import ioc_finder" 2>/dev/null; then
    python3 - <<'PYEOF'
from ioc_finder import find_iocs
import json, sys

with open('/tmp/ioc_input.txt', 'r', errors='replace') as f:
    text = f.read()

iocs = find_iocs(text)

# 결과 필터링 및 정리
result = {
    'ipv4': list(iocs.get('ipv4s', [])),
    'ipv6': list(iocs.get('ipv6s', [])),
    'domains': list(iocs.get('domains', [])),
    'urls': list(iocs.get('urls', [])),
    'emails': list(iocs.get('email_addresses', [])),
    'md5': list(iocs.get('md5s', [])),
    'sha1': list(iocs.get('sha1s', [])),
    'sha256': list(iocs.get('sha256s', [])),
}

total = sum(len(v) for v in result.values())
print(f"[+] 총 {total}개의 IOC 추출 완료")
with open('/tmp/ioc_raw.json', 'w') as f:
    json.dump(result, f, indent=2)
PYEOF
else
    echo "[!] ioc-finder 미설치. pip install ioc-finder 실행 후 재시도하세요."
    echo "[*] fallback: 정규식 기반 추출로 전환합니다."
fi
```

### 3단계: 정규식 기반 IOC 추출 (fallback)

```bash
python3 - <<'PYEOF'
import re, json

with open('/tmp/ioc_input.txt', 'r', errors='replace') as f:
    text = f.read()

patterns = {
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    'domains': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|kr|ru|cn|info|biz|xyz|top|club|online|site|tech|dev|gov|edu|mil)\b',
    'urls': r'https?://[^\s\'"<>]+',
    'emails': r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    'md5': r'\b[0-9a-fA-F]{32}\b',
    'sha1': r'\b[0-9a-fA-F]{40}\b',
    'sha256': r'\b[0-9a-fA-F]{64}\b',
}

result = {}
for key, pat in patterns.items():
    matches = list(set(re.findall(pat, text)))
    result[key] = matches

total = sum(len(v) for v in result.values())
print(f"[+] 총 {total}개의 IOC 추출 완료 (정규식 방식)")
with open('/tmp/ioc_raw.json', 'w') as f:
    json.dump(result, f, indent=2)
PYEOF
```

### 4단계: 디팡(Defang) 처리

```bash
python3 - <<'PYEOF'
import json, re

with open('/tmp/ioc_raw.json') as f:
    iocs = json.load(f)

def defang(value):
    # IP: 점을 [.] 로 치환
    value = re.sub(r'\.', '[.]', value)
    # URL 스킴 치환
    value = re.sub(r'https?://', 'hxxp[://]', value)
    return value

defanged = {}
for key, values in iocs.items():
    if key in ('md5', 'sha1', 'sha256'):
        defanged[key] = values  # 해시는 디팡 불필요
    else:
        defanged[key] = [defang(v) for v in values]

with open('/tmp/ioc_defanged.json', 'w') as f:
    json.dump(defanged, f, indent=2, ensure_ascii=False)
print("[+] 디팡 처리 완료: /tmp/ioc_defanged.json")
PYEOF
```

### 5단계: 구조화된 IOC 보고서 출력

```bash
python3 - <<'PYEOF'
import json

with open('/tmp/ioc_defanged.json') as f:
    iocs = json.load(f)

labels = {
    'ipv4': 'IPv4 주소',
    'ipv6': 'IPv6 주소',
    'domains': '도메인',
    'urls': 'URL',
    'emails': '이메일',
    'md5': 'MD5 해시',
    'sha1': 'SHA1 해시',
    'sha256': 'SHA256 해시',
}

print("=" * 60)
print("IOC 추출 결과 보고서")
print("=" * 60)
for key, label in labels.items():
    values = iocs.get(key, [])
    if values:
        print(f"\n[{label}] ({len(values)}개)")
        for v in values:
            print(f"  {v}")

print("\n[+] 원본 JSON: /tmp/ioc_raw.json")
print("[+] 디팡 JSON: /tmp/ioc_defanged.json")
PYEOF
```

## 완료 조건

- `/tmp/ioc_raw.json` 파일에 추출된 IOC가 카테고리별로 저장됨
- `/tmp/ioc_defanged.json` 파일에 디팡 처리된 IOC가 저장됨
- 터미널에 카테고리별 IOC 목록이 출력됨

## 실패 모드

| 문제 | 원인 | 해결책 |
|------|------|--------|
| ioc-finder ImportError | 패키지 미설치 | `pip install ioc-finder` 실행 |
| 빈 결과 | 패턴 불일치 또는 인코딩 문제 | 입력 파일 인코딩 확인 (`file -i`) |
| 과도한 false positive | 정규식 패턴 과민 | ioc-finder 사용 권장, 또는 allowlist 적용 |
| URL 수집 실패 | curl 미설치 또는 네트워크 차단 | `sudo apt install curl` 또는 수동 복사 |

## 참고 사항

- 디팡된 IOC는 실수로 클릭해도 연결되지 않아 안전하게 공유할 수 있습니다.
- 내부 IP 범위(10.x, 172.16-31.x, 192.168.x)는 수동으로 검토 후 제외하세요.
- 추출된 해시는 VirusTotal 조회를 위해 `malware-hash` 스킬과 연계할 수 있습니다.
- 대용량 로그(1GB 이상)는 먼저 `grep`으로 의심 라인을 필터링한 후 적용하세요.
