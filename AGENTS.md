<!-- Generated: 2026-04-13 | Updated: 2026-04-13 -->

# security-skill

## Purpose
AI 에이전트용 보안 스킬 모음집. 각 스킬은 `SKILL.md` 마크다운 지시서로, 에이전트가 검증된 보안 도구를 활용하여 정찰, 취약점 분석, 웹 보안 점검, 암호학, 침해 대응, 컴플라이언스 업무를 수행하도록 안내한다.

## Key Files

| File | Description |
|------|-------------|
| `package.json` | 프로젝트 메타데이터 및 워크스페이스 설정 |
| `CLAUDE.md` | Claude Code 개발 규칙 |
| `README.md` | 프로젝트 소개 및 스킬 목록 |
| `LICENSE` | MIT 라이선스 |
| `.gitignore` | Git 제외 패턴 |

## Subdirectories

### Skills (스킬 디렉토리)

#### Recon (정찰)
| Directory | Purpose |
|-----------|---------|
| `subdomain-enum/` | 서브도메인 열거 — subfinder, amass |
| `dns-recon/` | DNS 레코드 정찰 및 zone transfer |
| `whois-lookup/` | 도메인/IP WHOIS 조회 |
| `port-scan/` | 포트 스캔 및 서비스 탐지 — nmap |
| `cert-transparency/` | Certificate Transparency 로그 조회 |
| `osint-email/` | 이메일 기반 OSINT 수집 |

#### Vulnerability Analysis (취약점 분석)
| Directory | Purpose |
|-----------|---------|
| `cve-lookup/` | CVE 상세 정보 조회 — NVD API |
| `nuclei-scan/` | Nuclei 템플릿 기반 취약점 스캔 |
| `dependency-audit/` | 의존성 취약점 감사 — npm audit, pip-audit, trivy |
| `secret-scan/` | 소스코드 시크릿 탐지 — trufflehog, gitleaks |

#### Web Security (웹 보안)
| Directory | Purpose |
|-----------|---------|
| `security-headers/` | HTTP 보안 헤더 분석 |
| `ssl-check/` | SSL/TLS 인증서 및 설정 점검 |
| `cors-check/` | CORS 설정 오류 탐지 |
| `waf-detect/` | WAF 탐지 |

#### Cryptography (암호학)
| Directory | Purpose |
|-----------|---------|
| `hash-identify/` | 해시 타입 식별 및 검증 |
| `encoding-toolkit/` | 인코딩/디코딩 변환 |
| `cert-parse/` | X.509 인증서 파싱 및 체인 검증 |

#### Incident Response (침해 대응)
| Directory | Purpose |
|-----------|---------|
| `ioc-extract/` | IOC(침해 지표) 추출 |
| `malware-hash/` | 악성코드 해시 평판 조회 — VirusTotal |
| `log-analysis/` | 보안 로그 분석 및 이상 탐지 |

#### Compliance (컴플라이언스)
| Directory | Purpose |
|-----------|---------|
| `owasp-check/` | OWASP Top 10 체크리스트 점검 |
| `isms-checklist/` | ISMS-P 인증 항목 점검 |

### Infrastructure
| Directory | Purpose |
|-----------|---------|
| `scripts/` | 검증 및 유틸리티 스크립트 (see `scripts/AGENTS.md`) |
| `docs/` | 설치/기여 문서 (see `docs/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- 스킬 디렉토리는 루트에 flat하게 배치 — 중첩 금지
- 각 스킬 디렉토리에는 `SKILL.md` 하나만 존재
- 실행 코드는 기존 보안 도구에 위임, 스킬 자체에 소스코드 포함 금지
- 새 스킬 추가 시 `docs/contributing.md` 참조

### Testing Requirements
```bash
./scripts/validate-skills.sh   # 구조 검증
npm test                       # 문서 컨벤션 테스트
```

### Common Patterns
- SKILL.md YAML 프론트매터: `name`, `description`, `license`, `metadata.category`
- 크리덴셜 해결 순서: 환경변수 → `~/.config/security-skill/secrets.env` → 사용자 질의
- 환경변수 접두사: `SECSKILL_`

## Dependencies

### External
- Node.js >= 18 (검증 스크립트 실행)
- Go toolchain (subfinder, nuclei, httpx, trufflehog 설치)
- Python 3 (pip-audit, holehe, hashid, wafw00f 등)
- System packages: nmap, whois, dnsutils, openssl, jq, curl

<!-- MANUAL: -->
