# security-skill

> 보안인의, 보안인에 의한, 보안인을 위한 스킬 모음집.

**AI 에이전트가 바로 사용할 수 있는 보안 스킬 컬렉션.**

각 스킬은 하나의 `SKILL.md` 마크다운 파일로, AI 에이전트(Claude Code, Cursor, Windsurf 등)에게 보안 도구 사용법을 알려주는 지시서입니다. 실행 코드는 기존의 검증된 보안 도구(nmap, nuclei, subfinder 등)에 위임합니다.

## 구조

```
security-skill/
├── <skill-name>/          # 스킬 디렉토리 (루트에 flat 하게 배치)
│   └── SKILL.md           # 스킬 정의 파일 (유일한 파일)
├── scripts/               # 검증 및 유틸리티 스크립트
├── docs/                  # 문서
└── packages/              # 스킬이 의존하는 실행 패키지 (향후)
```

## 스킬 목록

### Recon (정찰)
| 스킬 | 설명 |
|------|------|
| [`subdomain-enum`](subdomain-enum/) | 서브도메인 열거 (subfinder, amass) |
| [`dns-recon`](dns-recon/) | DNS 레코드 정찰 및 zone transfer 시도 |
| [`whois-lookup`](whois-lookup/) | 도메인/IP WHOIS 조회 |
| [`port-scan`](port-scan/) | 포트 스캔 및 서비스 탐지 (nmap) |
| [`cert-transparency`](cert-transparency/) | Certificate Transparency 로그 조회 |
| [`osint-email`](osint-email/) | 이메일 주소 기반 OSINT 수집 |

### Vulnerability Analysis (취약점 분석)
| 스킬 | 설명 |
|------|------|
| [`cve-lookup`](cve-lookup/) | CVE 상세 정보 조회 (NVD/MITRE) |
| [`nuclei-scan`](nuclei-scan/) | Nuclei 템플릿 기반 취약점 스캔 |
| [`dependency-audit`](dependency-audit/) | 의존성 취약점 감사 (npm audit, pip-audit, trivy) |
| [`secret-scan`](secret-scan/) | 소스코드 내 시크릿/크리덴셜 탐지 |

### Web Security (웹 보안)
| 스킬 | 설명 |
|------|------|
| [`security-headers`](security-headers/) | HTTP 보안 헤더 분석 |
| [`ssl-check`](ssl-check/) | SSL/TLS 인증서 및 설정 점검 |
| [`cors-check`](cors-check/) | CORS 설정 오류 탐지 |
| [`waf-detect`](waf-detect/) | WAF(Web Application Firewall) 탐지 |

### Cryptography (암호학)
| 스킬 | 설명 |
|------|------|
| [`hash-identify`](hash-identify/) | 해시 타입 식별 및 검증 |
| [`encoding-toolkit`](encoding-toolkit/) | 인코딩/디코딩 변환 (Base64, URL, Hex 등) |
| [`cert-parse`](cert-parse/) | X.509 인증서 파싱 및 체인 검증 |

### Incident Response (침해 대응)
| 스킬 | 설명 |
|------|------|
| [`ioc-extract`](ioc-extract/) | 텍스트에서 IOC(Indicator of Compromise) 추출 |
| [`malware-hash`](malware-hash/) | 악성코드 해시 평판 조회 (VirusTotal) |
| [`log-analysis`](log-analysis/) | 보안 로그 분석 및 이상 탐지 |

### Compliance (컴플라이언스)
| 스킬 | 설명 |
|------|------|
| [`owasp-check`](owasp-check/) | OWASP Top 10 체크리스트 기반 점검 |
| [`isms-checklist`](isms-checklist/) | ISMS-P 인증 항목 점검 체크리스트 |

## 설치

### Claude Code
```bash
# 개별 스킬 설치
cp -r subdomain-enum/SKILL.md ~/.claude/skills/subdomain-enum/SKILL.md

# 전체 설치
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

### 직접 사용
각 `SKILL.md`를 읽고 워크플로우 섹션의 명령어를 순서대로 실행하면 됩니다.

## 스킬 작성 가이드

새 스킬을 기여하려면 [docs/contributing.md](docs/contributing.md)를 참고하세요.

```bash
# 스킬 유효성 검증
./scripts/validate-skills.sh
```

## 라이선스

MIT License - [LICENSE](LICENSE) 참조

## 기여

보안 커뮤니티의 기여를 환영합니다. 새 스킬 PR, 기존 스킬 개선, 버그 리포트 모두 감사합니다.
