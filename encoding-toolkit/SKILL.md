---
name: encoding-toolkit
description: Encode and decode strings across Base64, URL, Hex, HTML entities, ROT13, and JWT formats
license: MIT
metadata:
  category: crypto
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

입력 문자열의 인코딩 형식을 자동 감지하고, Base64·URL 인코딩·Hex·HTML 엔터티·ROT13·JWT 등 다양한 형식으로 인코딩/디코딩 변환을 수행합니다. `base64`, `python3`, `xxd` 등 기본 도구만 사용합니다.

## 언제 사용하나요

- 웹 요청/응답에서 발견한 인코딩된 문자열을 분석할 때
- CTF에서 다중 인코딩 레이어를 벗겨낼 때
- JWT 토큰의 헤더·페이로드를 검사할 때
- 페이로드를 WAF 우회를 위해 여러 형식으로 변환할 때

## 사전 조건

- `python3` (표준 라이브러리 사용, 별도 설치 불필요)
- `base64` 명령 (Linux/macOS 기본 내장)
- `xxd` 명령 (Linux/macOS 기본 내장)

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `INPUT` | 변환할 입력 문자열 | `SGVsbG8gV29ybGQ=` |
| `MODE` | 수행할 작업 (아래 목록 참고) | `base64-decode` |

## 워크플로우

### 1단계: 인코딩 자동 감지

```bash
INPUT="SGVsbG8gV29ybGQ="

echo "=== 인코딩 자동 감지 ==="
python3 - <<PYEOF
import re, base64, urllib.parse, sys

data = """${INPUT}"""

results = []

# Base64 감지
if re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', data) and len(data) % 4 == 0 and len(data) > 0:
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        results.append(f"[Base64 가능성] 디코딩: {decoded[:80]}")
    except Exception:
        pass

# URL 인코딩 감지
if '%' in data:
    try:
        decoded = urllib.parse.unquote(data)
        results.append(f"[URL 인코딩 가능성] 디코딩: {decoded[:80]}")
    except Exception:
        pass

# Hex 감지
if re.fullmatch(r'[0-9a-fA-F]+', data) and len(data) % 2 == 0:
    try:
        decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
        results.append(f"[Hex 가능성] 디코딩: {decoded[:80]}")
    except Exception:
        pass

# HTML 엔터티 감지
if '&' in data and ';' in data:
    import html
    decoded = html.unescape(data)
    results.append(f"[HTML 엔터티 가능성] 디코딩: {decoded[:80]}")

# JWT 감지
if data.count('.') == 2 and re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', data):
    results.append("[JWT 가능성] 점(.) 3부분 구조 확인됨 → 4단계 JWT 디코딩 사용")

if results:
    for r in results:
        print(r)
else:
    print("자동 감지 실패 → 수동으로 MODE 지정하여 변환하세요")
PYEOF
```

### 2단계: Base64 인코딩/디코딩

```bash
echo ""
echo "=== Base64 ==="

# 인코딩
echo -n "$INPUT" | base64
echo "(위: Base64 인코딩 결과)"

# 디코딩 (Base64 문자열인 경우)
echo "$INPUT" | base64 -d 2>/dev/null && echo "" || echo "(디코딩 실패: 유효한 Base64 문자열이 아님)"

# URL-safe Base64 처리 (패딩 자동 보정)
python3 -c "
import base64, sys
s = '${INPUT}'
s = s.replace('-', '+').replace('_', '/')
padding = 4 - len(s) % 4
if padding != 4:
    s += '=' * padding
try:
    print('URL-safe Base64 디코딩:', base64.b64decode(s).decode('utf-8', errors='replace'))
except Exception as e:
    print('URL-safe Base64 디코딩 실패:', e)
"
```

### 3단계: URL 인코딩, Hex, HTML, ROT13 변환

```bash
echo ""
echo "=== 다중 형식 변환 ==="
python3 - <<PYEOF
import urllib.parse, html, codecs, binascii

data = """${INPUT}"""

print("--- URL 인코딩 ---")
print("인코딩:", urllib.parse.quote(data, safe=''))
print("디코딩:", urllib.parse.unquote(data))

print("")
print("--- Hex ---")
hex_enc = data.encode('utf-8').hex()
print("인코딩 (hex):", hex_enc)
print("0x 형식     :", ' '.join('0x'+hex_enc[i:i+2] for i in range(0, len(hex_enc), 2)))
try:
    decoded_hex = bytes.fromhex(data).decode('utf-8', errors='replace')
    print("디코딩 (hex→str):", decoded_hex)
except ValueError:
    print("디코딩 (hex→str): 유효한 Hex 문자열이 아님")

print("")
print("--- HTML 엔터티 ---")
print("인코딩:", html.escape(data))
print("디코딩:", html.unescape(data))

print("")
print("--- ROT13 ---")
print("변환:", codecs.encode(data, 'rot_13'))
PYEOF

echo ""
echo "--- xxd Hex 덤프 ---"
echo -n "$INPUT" | xxd | head -5
```

### 4단계: JWT 디코딩

```bash
echo ""
echo "=== JWT 디코딩 ==="
# INPUT에 JWT 토큰을 설정하세요
JWT_TOKEN="$INPUT"

python3 - <<PYEOF
import base64, json, sys

token = """${JWT_TOKEN}"""
parts = token.split('.')

if len(parts) != 3:
    print("유효한 JWT 형식이 아닙니다 (점으로 구분된 3부분 필요)")
    sys.exit(0)

def decode_part(part):
    # URL-safe Base64 패딩 보정
    part = part.replace('-', '+').replace('_', '/')
    padding = 4 - len(part) % 4
    if padding != 4:
        part += '=' * padding
    try:
        decoded = base64.b64decode(part)
        return json.loads(decoded)
    except Exception:
        return decoded.decode('utf-8', errors='replace') if isinstance(decoded, bytes) else str(decoded)

print("=== JWT 헤더 ===")
print(json.dumps(decode_part(parts[0]), indent=2, ensure_ascii=False))

print("")
print("=== JWT 페이로드 ===")
print(json.dumps(decode_part(parts[1]), indent=2, ensure_ascii=False))

print("")
print("=== JWT 서명 ===")
print(f"(Base64URL 원본): {parts[2]}")
print("※ 서명 검증은 시크릿 키 또는 공개키 필요")
PYEOF
```

## 완료 조건

- 입력 문자열에 대해 가능한 인코딩 형식이 자동 감지됨
- Base64·URL·Hex·HTML·ROT13 각각의 인코딩/디코딩 결과가 출력됨
- JWT인 경우 헤더·페이로드·서명이 파싱되어 출력됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| Base64 디코딩 결과가 깨진 문자 | 이진 데이터이거나 추가 인코딩 레이어 존재. Hex 덤프로 원시 바이트 확인 |
| JWT 페이로드 파싱 실패 | 비표준 JWT(암호화된 JWE 등). 헤더의 `alg`/`enc` 필드 확인 |
| URL 디코딩 후 또 인코딩됨 | 이중 URL 인코딩. 2회 반복 디코딩 필요 |
| ROT13 결과가 의미 없음 | ROT13이 아닌 다른 시저 암호. 모든 이동값(1-25) 시도 필요 |

## 참고

- 다중 인코딩(Base64 후 URL 인코딩 등)의 경우 각 단계를 순서대로 반복 적용.
- `cyberchef`(https://gchq.github.io/CyberChef/) 는 GUI 기반 다중 변환에 유용.
- JWT 알고리즘 `alg: none` 공격 여부 확인 시 헤더의 alg 값을 반드시 검사.
