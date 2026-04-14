[English](README.md) | 한국어

# security-skill

> 보안인의, 보안인에 의한, 보안인을 위한 스킬 모음집.

**AI 에이전트를 위한 50개 보안 스킬 — 복사하고, 설치하고, 바로 테스트하세요.**

각 스킬은 `SKILL.md` 마크다운 파일로, AI 에이전트(Claude Code, Cursor, Windsurf 등)에게 보안 도구 사용법을 알려주는 지시서입니다. 실행 코드 없이 검증된 도구(nmap, nuclei, subfinder 등)에 위임합니다.

## 빠른 시작

```bash
# Claude Code에 전체 스킬 설치
git clone https://github.com/woohyun212/security-skill.git
cd security-skill
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

설치 후 AI 에이전트에게 자연어로 요청하세요:

| 이렇게 말하면... | 활성화되는 스킬 |
|------------------|----------------|
| "example.com의 열린 포트를 스캔해줘" | `port-scan` |
| "example.com의 서브도메인을 찾아줘" | `subdomain-enum` |
| "이 사이트의 SSL 인증서를 확인해줘" | `ssl-check` |
| "이 앱에 OWASP Top 10 점검을 실행해줘" | `owasp-check` |
| "CVE-2024-1234를 조회해줘" | `cve-lookup` |
| "의존성 취약점을 스캔해줘" | `dependency-audit` |
| "APT28의 TTP를 MITRE ATT&CK에서 프로파일링해줘" | `mitre-attack-lookup` |
| "이 발견 사항으로 침투 테스트 보고서를 작성해줘" | `pentest-report` |
| "이 엔드포인트에 SSRF 테스트를 해줘" | `web-vuln-ssrf` |
| "결제 API의 위협 모델을 만들어줘" | `threat-model` |

## 스킬 목록 (50개)

### 정찰 (8)

> 사용 예시: *"example.com의 서브도메인을 열거해줘"* · *"10.0.0.1 포트 스캔해줘"* · *"example.com WHOIS 조회해줘"*

| 스킬 | 설명 |
|------|------|
| [`subdomain-enum`](subdomain-enum/) | 서브도메인 열거 (subfinder, amass) |
| [`dns-recon`](dns-recon/) | DNS 레코드 정찰 및 zone transfer 시도 |
| [`whois-lookup`](whois-lookup/) | 도메인/IP WHOIS 조회 |
| [`port-scan`](port-scan/) | 포트 스캔 및 서비스 탐지 (nmap) |
| [`cert-transparency`](cert-transparency/) | Certificate Transparency 로그 조회 |
| [`osint-email`](osint-email/) | 이메일 주소 기반 OSINT 수집 |
| [`subdomain-takeover`](subdomain-takeover/) | 댕글링 DNS 기반 서브도메인 탈취 탐지 |
| [`cloud-pentest`](cloud-pentest/) | AWS, Azure, GCP 클라우드 보안 테스트 |

### 취약점 분석 (5)

> 사용 예시: *"CVE-2024-3094 조회해줘"* · *"nuclei 템플릿으로 스캔해줘"* · *"npm 의존성 취약점 감사해줘"*

| 스킬 | 설명 |
|------|------|
| [`cve-lookup`](cve-lookup/) | CVE 상세 정보 조회 (NVD/MITRE) |
| [`nuclei-scan`](nuclei-scan/) | Nuclei 템플릿 기반 취약점 스캔 |
| [`dependency-audit`](dependency-audit/) | 의존성 취약점 감사 (npm audit, pip-audit, trivy) |
| [`secret-scan`](secret-scan/) | 소스코드 내 시크릿/크리덴셜 탐지 |
| [`supply-chain-audit`](supply-chain-audit/) | 소프트웨어 공급망 보안 (SLSA 준수, SBOM 생성) |

### 웹 보안 (16)

> 사용 예시: *"이 엔드포인트에 SSRF 테스트해줘"* · *"CORS 설정 확인해줘"* · *"OAuth 플로우 취약점 테스트해줘"*

| 스킬 | 설명 |
|------|------|
| [`security-headers`](security-headers/) | HTTP 보안 헤더 분석 |
| [`ssl-check`](ssl-check/) | SSL/TLS 인증서 및 설정 점검 |
| [`cors-check`](cors-check/) | CORS 설정 오류 탐지 |
| [`waf-detect`](waf-detect/) | WAF(Web Application Firewall) 탐지 |
| [`mobile-pentest`](mobile-pentest/) | 모바일 앱 보안 테스트 (Android/iOS) |
| [`bug-bounty-methodology`](bug-bounty-methodology/) | 버그 바운티 헌팅 방법론 및 워크플로 |
| [`web-vuln-idor`](web-vuln-idor/) | IDOR 취약점 탐지 (V1-V8 변형) |
| [`web-vuln-ssrf`](web-vuln-ssrf/) | SSRF 탐지 (IP 우회 기법, 클라우드 메타데이터) |
| [`web-vuln-business-logic`](web-vuln-business-logic/) | 비즈니스 로직 취약점 탐지 |
| [`web-vuln-race-conditions`](web-vuln-race-conditions/) | 레이스 컨디션 탐지 (TOCTOU, 이중 지불) |
| [`web-vuln-oauth`](web-vuln-oauth/) | OAuth 2.0/OIDC 취약점 탐지 |
| [`web-vuln-graphql`](web-vuln-graphql/) | GraphQL API 보안 테스트 |
| [`web-vuln-http-smuggling`](web-vuln-http-smuggling/) | HTTP 요청 스머글링 (CL.TE, TE.CL, H2.CL) |
| [`web-vuln-cache-poisoning`](web-vuln-cache-poisoning/) | 웹 캐시 포이즈닝 및 캐시 디셉션 |
| [`web-vuln-ssti`](web-vuln-ssti/) | SSTI(Server-Side Template Injection) 탐지 |
| [`llm-ai-security`](llm-ai-security/) | LLM/AI 보안 테스트 (OWASP ASI01-ASI10) |

### 인증 및 세션 (3)

> 사용 예시: *"이 로그인에 MFA 우회 테스트해줘"* · *"SAML SSO에 XSW 공격 확인해줘"* · *"BloodHound로 AD 정찰해줘"*

| 스킬 | 설명 |
|------|------|
| [`web-vuln-saml-sso`](web-vuln-saml-sso/) | SAML/SSO 취약점 탐지 (XSW 공격) |
| [`web-vuln-mfa-bypass`](web-vuln-mfa-bypass/) | 다중 인증(MFA) 우회 기법 |
| [`ad-pentest`](ad-pentest/) | Active Directory 침투 테스트 |

### 암호학 (3)

> 사용 예시: *"이 해시 타입을 식별해줘: 5f4dcc3b..."* · *"이 base64 문자열을 디코딩해줘"* · *"이 X.509 인증서를 파싱해줘"*

| 스킬 | 설명 |
|------|------|
| [`hash-identify`](hash-identify/) | 해시 타입 식별 및 검증 |
| [`encoding-toolkit`](encoding-toolkit/) | 인코딩/디코딩 변환 (Base64, URL, Hex 등) |
| [`cert-parse`](cert-parse/) | X.509 인증서 파싱 및 체인 검증 |

### 침해 대응 (6)

> 사용 예시: *"이 로그에서 IOC를 추출해줘"* · *"이 해시를 VirusTotal에서 확인해줘"* · *"이 공격을 MITRE ATT&CK에 매핑해줘"*

| 스킬 | 설명 |
|------|------|
| [`ioc-extract`](ioc-extract/) | 텍스트에서 IOC(침해 지표) 추출 |
| [`malware-hash`](malware-hash/) | 악성코드 해시 평판 조회 (VirusTotal) |
| [`log-analysis`](log-analysis/) | 보안 로그 분석 및 이상 탐지 |
| [`malware-analysis`](malware-analysis/) | 악성코드 분석 파이프라인 (정적 + 동적 + 행위) |
| [`siem-rule`](siem-rule/) | SIEM 탐지 룰 엔지니어링 (Sigma, Splunk, Elastic, Sentinel) |
| [`mitre-attack-lookup`](mitre-attack-lookup/) | mitrize 기반 MITRE ATT&CK 지식 베이스 조회 |

### 컴플라이언스 및 보고 (5)

> 사용 예시: *"OWASP Top 10 평가를 실행해줘"* · *"STRIDE로 위협 모델을 만들어줘"* · *"침투 테스트 보고서를 작성해줘"*

| 스킬 | 설명 |
|------|------|
| [`owasp-check`](owasp-check/) | OWASP Top 10 체크리스트 기반 점검 |
| [`isms-checklist`](isms-checklist/) | ISMS-P 인증 항목 점검 체크리스트 |
| [`threat-model`](threat-model/) | 위협 모델링 (STRIDE, DREAD, PASTA, Attack Trees) |
| [`pentest-report`](pentest-report/) | 전문 침투 테스트 보고서 작성 |
| [`bug-bounty-validation`](bug-bounty-validation/) | 버그 바운티 발견 사항 검증 (7-Question Gate) |

### 코드 보안 (4)

> 사용 예시: *"이 PR을 보안 리뷰해줘"* · *"SAST/DAST 파이프라인을 설정해줘"* · *"이 스마트 컨트랙트를 감사해줘"*

| 스킬 | 설명 |
|------|------|
| [`secure-code-review`](secure-code-review/) | 10개 도메인 보안 코드 리뷰 |
| [`devsecops-pipeline`](devsecops-pipeline/) | CI/CD 보안 파이프라인 (SAST, SCA, DAST, SBOM) |
| [`web3-smart-contract`](web3-smart-contract/) | 스마트 컨트랙트 감사 (10가지 DeFi 취약점 클래스) |
| [`exploit-chain-building`](exploit-chain-building/) | A→B→C 익스플로잇 체인 빌딩 방법론 |

## 설치

### Claude Code (권장)

위의 [빠른 시작](#빠른-시작)을 참고하세요. 개별 스킬 설치:

```bash
# 스킬 하나만 설치
cp port-scan/SKILL.md ~/.claude/skills/port-scan/SKILL.md

# 그리고 "10.0.0.1의 열린 포트를 스캔해줘"라고 요청하세요
```

### 다른 AI 에이전트 (Cursor, Windsurf 등)

`SKILL.md`를 에이전트의 스킬/지시 디렉토리에 복사하거나, 시스템 프롬프트에 내용을 붙여넣으세요.

### 직접 사용

`SKILL.md`를 읽고 워크플로우 섹션의 명령어를 순서대로 실행하면 됩니다.

## 구조

```
security-skill/
├── <skill-name>/
│   ├── SKILL.md           # 스킬 정의 (워크플로우 + 지시사항)
│   └── REFERENCE.md       # 선택적 참조 데이터 (테이블, 템플릿)
├── scripts/               # 검증 및 유틸리티 스크립트
└── docs/                  # 문서
```

## 기여

새 스킬을 기여하려면 [docs/contributing.md](docs/contributing.md)를 참고하세요.

```bash
# 스킬 유효성 검증
./scripts/validate-skills.sh
```

## 크레딧

다음 프로젝트를 참고하여 스킬을 작성하였습니다:
- [JoasASantos/ClaudeAdvancedPlugins](https://github.com/JoasASantos/ClaudeAdvancedPlugins) — 공격/방어 보안 플러그인
- [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) — 버그 바운티 헌팅 방법론
- [woohyun212/mitrize](https://github.com/woohyun212/mitrize) — MITRE ATT&CK 마크다운 지식 베이스

## 라이선스

MIT License - [LICENSE](LICENSE) 참조

## 기여

보안 커뮤니티의 기여를 환영합니다. 새 스킬 PR, 기존 스킬 개선, 버그 리포트 모두 감사합니다.
