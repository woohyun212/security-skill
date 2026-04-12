English | [한국어](README.ko.md)

# security-skill

> By security professionals, of security professionals, for security professionals.

**A security skill collection ready for AI agents to use immediately.**

Each skill is a single `SKILL.md` markdown file — an instruction set that teaches AI agents (Claude Code, Cursor, Windsurf, etc.) how to use security tools. Execution is delegated to proven, existing security tools (nmap, nuclei, subfinder, etc.).

## Structure

```
security-skill/
├── <skill-name>/          # Skill directory (flat layout at root)
│   └── SKILL.md           # Skill definition file (the only file)
├── scripts/               # Validation and utility scripts
├── docs/                  # Documentation
└── packages/              # Executable packages for skill dependencies (future)
```

## Skill List (50 skills)

### Recon (8)
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
| Skill | Description |
|-------|-------------|
| [`cve-lookup`](cve-lookup/) | CVE detailed information lookup (NVD/MITRE) |
| [`nuclei-scan`](nuclei-scan/) | Nuclei template-based vulnerability scanning |
| [`dependency-audit`](dependency-audit/) | Dependency vulnerability audit (npm audit, pip-audit, trivy) |
| [`secret-scan`](secret-scan/) | Secret/credential detection in source code |
| [`supply-chain-audit`](supply-chain-audit/) | Software supply chain security with SLSA compliance and SBOM |

### Web Security (16)
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
| Skill | Description |
|-------|-------------|
| [`web-vuln-saml-sso`](web-vuln-saml-sso/) | SAML/SSO vulnerability detection (XSW attacks) |
| [`web-vuln-mfa-bypass`](web-vuln-mfa-bypass/) | Multi-factor authentication bypass techniques |
| [`ad-pentest`](ad-pentest/) | Active Directory penetration testing |

### Cryptography (3)
| Skill | Description |
|-------|-------------|
| [`hash-identify`](hash-identify/) | Hash type identification and verification |
| [`encoding-toolkit`](encoding-toolkit/) | Encoding/decoding conversion (Base64, URL, Hex, etc.) |
| [`cert-parse`](cert-parse/) | X.509 certificate parsing and chain validation |

### Incident Response (6)
| Skill | Description |
|-------|-------------|
| [`ioc-extract`](ioc-extract/) | IOC (Indicator of Compromise) extraction from text |
| [`malware-hash`](malware-hash/) | Malware hash reputation lookup (VirusTotal) |
| [`log-analysis`](log-analysis/) | Security log analysis and anomaly detection |
| [`malware-analysis`](malware-analysis/) | Malware analysis pipeline (static + dynamic + behavioral) |
| [`siem-rule`](siem-rule/) | SIEM detection rule engineering (Sigma, Splunk, Elastic, Sentinel) |
| [`mitre-attack-lookup`](mitre-attack-lookup/) | MITRE ATT&CK knowledge base lookup via mitrize |

### Compliance & Reporting (5)
| Skill | Description |
|-------|-------------|
| [`owasp-check`](owasp-check/) | OWASP Top 10 checklist-based assessment |
| [`isms-checklist`](isms-checklist/) | ISMS-P certification item checklist |
| [`threat-model`](threat-model/) | Threat modeling (STRIDE, DREAD, PASTA, Attack Trees) |
| [`pentest-report`](pentest-report/) | Professional penetration test report writing |
| [`bug-bounty-validation`](bug-bounty-validation/) | Bug bounty finding validation (7-Question Gate) |

### Code Security (4)
| Skill | Description |
|-------|-------------|
| [`secure-code-review`](secure-code-review/) | Security code review with 10-domain checklist |
| [`devsecops-pipeline`](devsecops-pipeline/) | CI/CD security pipeline (SAST, SCA, DAST, SBOM) |
| [`web3-smart-contract`](web3-smart-contract/) | Smart contract audit (10 DeFi vulnerability classes) |
| [`exploit-chain-building`](exploit-chain-building/) | A-to-B-to-C exploit chain building methodology |

## Installation

### Claude Code
```bash
# Install a single skill
cp -r subdomain-enum/SKILL.md ~/.claude/skills/subdomain-enum/SKILL.md

# Install all skills
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

### Direct Use
Read any `SKILL.md` and execute the commands in the workflow section in order.

## Skill Authoring Guide

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

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions from the security community are welcome. New skill PRs, improvements to existing skills, and bug reports are all appreciated.
