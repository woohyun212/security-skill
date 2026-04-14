English | [한국어](README.ko.md)

# security-skill

> By security professionals, of security professionals, for security professionals.

**50 security skills for AI agents — copy, install, and start testing.**

Each skill is a `SKILL.md` markdown file that teaches AI agents (Claude Code, Cursor, Windsurf, etc.) how to use security tools. No code to run — skills delegate to proven tools (nmap, nuclei, subfinder, etc.).

## Quick Start

```bash
# Install all skills to Claude Code
git clone https://github.com/woohyun212/security-skill.git
cd security-skill
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

Then just ask your AI agent naturally:

| You say... | Skill activated |
|------------|----------------|
| "Scan example.com for open ports" | `port-scan` |
| "Find subdomains of example.com" | `subdomain-enum` |
| "Check this site's SSL certificate" | `ssl-check` |
| "Run OWASP Top 10 check on this app" | `owasp-check` |
| "Look up CVE-2024-1234" | `cve-lookup` |
| "Scan dependencies for vulnerabilities" | `dependency-audit` |
| "Profile APT28's TTPs in MITRE ATT&CK" | `mitre-attack-lookup` |
| "Write a pentest report for these findings" | `pentest-report` |
| "Test this endpoint for SSRF" | `web-vuln-ssrf` |
| "Build a threat model for our payment API" | `threat-model` |

## Skill List (58 skills)

### Recon (8)

> Try: *"Enumerate subdomains of example.com"* · *"Run a port scan on 10.0.0.1"* · *"WHOIS lookup for example.com"*

| Skill | Description |
|-------|-------------|
| [`subdomain-enum`](subdomain-enum/) | Subdomain enumeration (subfinder, amass) |
| [`dns-recon`](dns-recon/) | DNS record reconnaissance and zone transfer attempts |
| [`whois-lookup`](whois-lookup/) | Domain/IP WHOIS lookup |
| [`port-scan`](port-scan/) | Port scanning and service detection (nmap) |
| [`cert-transparency`](cert-transparency/) | Certificate Transparency log lookup |
| [`osint-email`](osint-email/) | Email address-based OSINT collection |
| [`subdomain-takeover`](subdomain-takeover/) | Subdomain takeover detection for dangling DNS records |
| [`cloud-pentest`](cloud-pentest/) | Cloud security testing for AWS, Azure, and GCP |

### Vulnerability Analysis (5)

> Try: *"Look up CVE-2024-3094"* · *"Scan with nuclei templates"* · *"Audit npm dependencies for vulnerabilities"*

| Skill | Description |
|-------|-------------|
| [`cve-lookup`](cve-lookup/) | CVE detailed information lookup (NVD/MITRE) |
| [`nuclei-scan`](nuclei-scan/) | Nuclei template-based vulnerability scanning |
| [`dependency-audit`](dependency-audit/) | Dependency vulnerability audit (npm audit, pip-audit, trivy) |
| [`secret-scan`](secret-scan/) | Secret/credential detection in source code |
| [`supply-chain-audit`](supply-chain-audit/) | Software supply chain security with SLSA compliance and SBOM |

### Web Security (16)

> Try: *"Test this endpoint for SSRF"* · *"Check CORS configuration"* · *"Test OAuth flow for vulnerabilities"*

| Skill | Description |
|-------|-------------|
| [`security-headers`](security-headers/) | HTTP security header analysis |
| [`ssl-check`](ssl-check/) | SSL/TLS certificate and configuration check |
| [`cors-check`](cors-check/) | CORS misconfiguration detection |
| [`waf-detect`](waf-detect/) | Web Application Firewall (WAF) detection |
| [`mobile-pentest`](mobile-pentest/) | Mobile application security testing (Android/iOS) |
| [`bug-bounty-methodology`](bug-bounty-methodology/) | Bug bounty hunting methodology and workflow |
| [`web-vuln-idor`](web-vuln-idor/) | IDOR vulnerability detection (V1-V8 variants) |
| [`web-vuln-ssrf`](web-vuln-ssrf/) | SSRF detection with IP bypass and cloud metadata exploitation |
| [`web-vuln-business-logic`](web-vuln-business-logic/) | Business logic vulnerability detection |
| [`web-vuln-race-conditions`](web-vuln-race-conditions/) | Race condition detection (TOCTOU, double-spend) |
| [`web-vuln-oauth`](web-vuln-oauth/) | OAuth 2.0/OIDC vulnerability detection |
| [`web-vuln-graphql`](web-vuln-graphql/) | GraphQL API security testing |
| [`web-vuln-http-smuggling`](web-vuln-http-smuggling/) | HTTP request smuggling (CL.TE, TE.CL, H2.CL) |
| [`web-vuln-cache-poisoning`](web-vuln-cache-poisoning/) | Web cache poisoning and cache deception |
| [`web-vuln-ssti`](web-vuln-ssti/) | Server-Side Template Injection detection |
| [`llm-ai-security`](llm-ai-security/) | LLM/AI security testing (OWASP ASI01-ASI10) |

### Authentication & Session (3)

> Try: *"Test MFA bypass on this login"* · *"Check SAML SSO for XSW attacks"* · *"Run AD pentest recon with BloodHound"*

| Skill | Description |
|-------|-------------|
| [`web-vuln-saml-sso`](web-vuln-saml-sso/) | SAML/SSO vulnerability detection (XSW attacks) |
| [`web-vuln-mfa-bypass`](web-vuln-mfa-bypass/) | Multi-factor authentication bypass techniques |
| [`ad-pentest`](ad-pentest/) | Active Directory penetration testing |

### Cryptography (4)

> Try: *"Identify this hash type: 5f4dcc3b..."* · *"Decode this base64 string"* · *"Check this crypto code for timing side-channels"*

| Skill | Description |
|-------|-------------|
| [`hash-identify`](hash-identify/) | Hash type identification and verification |
| [`encoding-toolkit`](encoding-toolkit/) | Encoding/decoding conversion (Base64, URL, Hex, etc.) |
| [`cert-parse`](cert-parse/) | X.509 certificate parsing and chain validation |
| [`constant-time-analysis`](constant-time-analysis/) | Timing side-channel detection in cryptographic code |

### Incident Response (6)

> Try: *"Extract IOCs from this log"* · *"Check this hash on VirusTotal"* · *"Map this attack to MITRE ATT&CK"*

| Skill | Description |
|-------|-------------|
| [`ioc-extract`](ioc-extract/) | IOC (Indicator of Compromise) extraction from text |
| [`malware-hash`](malware-hash/) | Malware hash reputation lookup (VirusTotal) |
| [`log-analysis`](log-analysis/) | Security log analysis and anomaly detection |
| [`malware-analysis`](malware-analysis/) | Malware analysis pipeline (static + dynamic + behavioral) |
| [`siem-rule`](siem-rule/) | SIEM detection rule engineering (Sigma, Splunk, Elastic, Sentinel) |
| [`mitre-attack-lookup`](mitre-attack-lookup/) | MITRE ATT&CK knowledge base lookup via mitrize |

### Compliance & Reporting (6)

> Try: *"Run OWASP Top 10 assessment"* · *"Build a threat model using STRIDE"* · *"Verify this code matches the spec"*

| Skill | Description |
|-------|-------------|
| [`owasp-check`](owasp-check/) | OWASP Top 10 checklist-based assessment |
| [`isms-checklist`](isms-checklist/) | ISMS-P certification item checklist |
| [`threat-model`](threat-model/) | Threat modeling (STRIDE, DREAD, PASTA, Attack Trees) |
| [`pentest-report`](pentest-report/) | Professional penetration test report writing |
| [`bug-bounty-validation`](bug-bounty-validation/) | Bug bounty finding validation (7-Question Gate) |
| [`spec-to-code-compliance`](spec-to-code-compliance/) | Verify code implementation matches security specifications |

### Code Security (10)

> Try: *"Security review this PR diff"* · *"Fuzz this parser for crashes"* · *"Audit this Solana contract"*

| Skill | Description |
|-------|-------------|
| [`secure-code-review`](secure-code-review/) | Security code review with 10-domain checklist |
| [`differential-review`](differential-review/) | Security-focused git diff analysis for regressions |
| [`insecure-defaults`](insecure-defaults/) | Detect weak crypto, fail-open patterns, and unsafe defaults |
| [`devsecops-pipeline`](devsecops-pipeline/) | CI/CD security pipeline (SAST, SCA, DAST, SBOM) |
| [`web3-smart-contract`](web3-smart-contract/) | Smart contract audit (10 DeFi vulnerability classes) |
| [`building-secure-contracts`](building-secure-contracts/) | Multi-chain contract security (Solana, Algorand, Cairo, Cosmos) |
| [`entry-point-analyzer`](entry-point-analyzer/) | Attack surface mapping via entry point classification |
| [`property-based-testing`](property-based-testing/) | Property-based fuzzing for crypto and smart contracts |
| [`testing-handbook`](testing-handbook/) | Fuzzers (AFL++, libFuzzer), sanitizers (ASan/MSan/UBSan), static analysis |
| [`exploit-chain-building`](exploit-chain-building/) | A-to-B-to-C exploit chain building methodology |

## Installation

### Claude Code (recommended)

See [Quick Start](#quick-start) above for full install. To install a single skill:

```bash
# Install one skill
cp port-scan/SKILL.md ~/.claude/skills/port-scan/SKILL.md

# Then ask: "Scan 10.0.0.1 for open ports"
```

### Other AI Agents (Cursor, Windsurf, etc.)

Copy any `SKILL.md` into your agent's skill/instruction directory, or paste its contents into the system prompt.

### Direct Use

Read any `SKILL.md` and run the commands in the Workflow section step by step.

## Structure

```
security-skill/
├── <skill-name>/
│   ├── SKILL.md           # Skill definition (workflow + instructions)
│   └── REFERENCE.md       # Optional reference data (tables, templates)
├── scripts/               # Validation and utility scripts
└── docs/                  # Documentation
```

## Contributing

To contribute a new skill, see [docs/contributing.md](docs/contributing.md).

```bash
# Validate skills
./scripts/validate-skills.sh
```

## Credits

Skills inspired by and adapted from:
- [JoasASantos/ClaudeAdvancedPlugins](https://github.com/JoasASantos/ClaudeAdvancedPlugins) — Offensive/defensive security plugins
- [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) — Bug bounty hunting methodology
- [woohyun212/mitrize](https://github.com/woohyun212/mitrize) — MITRE ATT&CK Markdown knowledge base
- [Trail of Bits](https://github.com/trailofbits/skills) via [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) — Smart contract security, differential review, testing methodology

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions from the security community are welcome. New skill PRs, improvements to existing skills, and bug reports are all appreciated.
