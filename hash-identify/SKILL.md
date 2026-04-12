---
name: hash-identify
description: Identify hash algorithm type from a hash string and optionally verify against a known plaintext
license: MIT
metadata:
  category: crypto
  locale: ko-KR
  phase: v1
---

## 이 스킬이 하는 일

해시 문자열을 입력받아 `hashid` 도구로 알고리즘 종류를 식별합니다. 사용자가 원문(plaintext)을 제공하면 Python `hashlib`으로 해시 일치 여부를 검증합니다. 주요 해시의 길이 참조표도 함께 제공합니다.

## 언제 사용하나요

- 크랙 도구(Hashcat, John the Ripper) 실행 전 해시 타입을 특정할 때
- CTF에서 미지의 해시 값을 분석할 때
- 데이터베이스 덤프에서 발견한 해시를 빠르게 분류할 때

## 사전 조건

- Python 3 및 pip 설치 필요 (`hashid` 설치 시)
- `hashid`: `pip install hashid`
- `python3 hashlib`는 표준 라이브러리로 별도 설치 불필요

## 입력

| 변수 | 설명 | 예시 |
|------|------|------|
| `HASH_VALUE` | 식별할 해시 문자열 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `PLAINTEXT` | (선택) 검증할 원문 | `password` |

## 워크플로우

### 1단계: hashid 설치 확인 및 설치

```bash
if ! command -v hashid &>/dev/null; then
  echo "hashid 미설치. 설치 중..."
  pip install hashid --quiet
else
  echo "hashid 설치됨"
fi
```

### 2단계: 해시 타입 식별

```bash
HASH_VALUE="5f4dcc3b5aa765d61d8327deb882cf99"

echo "=== 해시 타입 식별 ==="
echo "입력 해시: $HASH_VALUE"
echo "길이: ${#HASH_VALUE} 문자"
echo ""
hashid "$HASH_VALUE" -m 2>&1
# -m : Hashcat 모드 번호도 함께 출력
```

### 3단계: 주요 해시 길이 참조표

```bash
echo ""
echo "=== 주요 해시 길이 참조표 ==="
python3 - <<'PYEOF'
import hashlib

samples = {
    "MD5":       hashlib.md5(b"test").hexdigest(),
    "SHA-1":     hashlib.sha1(b"test").hexdigest(),
    "SHA-224":   hashlib.sha224(b"test").hexdigest(),
    "SHA-256":   hashlib.sha256(b"test").hexdigest(),
    "SHA-384":   hashlib.sha384(b"test").hexdigest(),
    "SHA-512":   hashlib.sha512(b"test").hexdigest(),
    "SHA3-256":  hashlib.sha3_256(b"test").hexdigest(),
    "SHA3-512":  hashlib.sha3_512(b"test").hexdigest(),
    "BLAKE2b":   hashlib.blake2b(b"test").hexdigest(),
    "BLAKE2s":   hashlib.blake2s(b"test").hexdigest(),
}

print(f"{'알고리즘':<12} {'길이(hex)':<10} {'예시 (일부)'}")
print("-" * 55)
for name, h in samples.items():
    print(f"{name:<12} {len(h):<10} {h[:24]}...")
PYEOF
```

### 4단계: (선택) 원문으로 해시 검증

```bash
PLAINTEXT="password"  # 검증할 원문이 있을 경우 설정

if [ -n "$PLAINTEXT" ] && [ -n "$HASH_VALUE" ]; then
  echo ""
  echo "=== 해시 검증: '$PLAINTEXT' vs '$HASH_VALUE' ==="
  python3 - <<PYEOF
import hashlib

plaintext = b"${PLAINTEXT}"
target    = "${HASH_VALUE}".lower().strip()
length    = len(target)

# 길이 기반 알고리즘 후보 결정
candidates = {
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224"],
    64:  ["sha256", "sha3_256"],
    96:  ["sha384"],
    128: ["sha512", "sha3_512", "blake2b", "blake2s"],
}

algos = candidates.get(length, [])
if not algos:
    print(f"길이 {length}에 해당하는 알고리즘 후보 없음")
else:
    matched = False
    for algo in algos:
        try:
            h = hashlib.new(algo, plaintext).hexdigest()
            if h == target:
                print(f"[MATCH] {algo.upper()}: '{plaintext.decode()}' -> {h}")
                matched = True
        except Exception as e:
            print(f"[ERROR] {algo}: {e}")
    if not matched:
        print(f"일치하는 해시 없음 (후보 알고리즘: {', '.join(a.upper() for a in algos)})")
        print("참고: bcrypt/Argon2/PBKDF2 등 느린 해시는 hashlib 미지원 → hashcat 사용 필요")
PYEOF
fi
```

## 완료 조건

- 입력 해시의 길이와 가능한 알고리즘 목록이 출력됨
- (원문 제공 시) 해시 일치/불일치 여부가 명확히 표시됨
- 주요 알고리즘 길이 참조표가 출력됨

## 실패 모드

| 증상 | 원인 및 해결 |
|------|-------------|
| `hashid: command not found` | 설치 실패. `pip install hashid --user` 재시도 또는 PATH 확인 |
| "No algorithms found" | 비표준 해시이거나 인코딩(Base64 등) 포함. 디코딩 후 재시도 |
| 검증에서 일치 없음 | 소금(salt) 포함 해시이거나 bcrypt·Argon2 같은 느린 해시. hashcat 사용 필요 |
| 해시가 너무 짧음 (< 32자) | CRC32·Adler32 등 체크섬일 가능성. hashid 로 확인 |

## 참고

- bcrypt 해시는 `$2b$` 또는 `$2a$` 로 시작하며 hashlib으로 검증 불가. `bcrypt` 패키지 사용.
- Hashcat 모드 번호: hashid `-m` 옵션 출력 참고. 예) MD5=0, SHA-1=100, bcrypt=3200.
- 소금이 포함된 해시(예: `sha256:10000:salt:hash`)는 형식을 분리해 각 부분을 별도 처리.
