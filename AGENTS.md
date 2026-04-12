<!-- Generated: 2026-04-13 | Updated: 2026-04-13 -->

# security-skill

## Purpose
A collection of security skills for AI agents. Each skill is a `SKILL.md` markdown instruction file that guides agents to perform reconnaissance, vulnerability analysis, web security checks, cryptography, incident response, and compliance tasks using proven security tools.

## Key Files

| File | Description |
|------|-------------|
| `package.json` | Project metadata and workspace configuration |
| `CLAUDE.md` | Claude Code development rules |
| `README.md` | Project introduction and skill list |
| `LICENSE` | MIT license |
| `.gitignore` | Git exclusion patterns |

## Subdirectories

### Skills

#### Recon
| Directory | Purpose |
|-----------|---------|
| `subdomain-enum/` | Subdomain enumeration — subfinder, amass |
| `dns-recon/` | DNS record reconnaissance and zone transfer |
| `whois-lookup/` | Domain/IP WHOIS lookup |
| `port-scan/` | Port scanning and service detection — nmap |
| `cert-transparency/` | Certificate Transparency log lookup |
| `osint-email/` | Email-based OSINT collection |

#### Vulnerability Analysis
| Directory | Purpose |
|-----------|---------|
| `cve-lookup/` | CVE detail lookup — NVD API |
| `nuclei-scan/` | Nuclei template-based vulnerability scanning |
| `dependency-audit/` | Dependency vulnerability audit — npm audit, pip-audit, trivy |
| `secret-scan/` | Source code secret detection — trufflehog, gitleaks |

#### Web Security
| Directory | Purpose |
|-----------|---------|
| `security-headers/` | HTTP security header analysis |
| `ssl-check/` | SSL/TLS certificate and configuration check |
| `cors-check/` | CORS misconfiguration detection |
| `waf-detect/` | WAF detection |

#### Cryptography
| Directory | Purpose |
|-----------|---------|
| `hash-identify/` | Hash type identification and verification |
| `encoding-toolkit/` | Encoding/decoding conversion |
| `cert-parse/` | X.509 certificate parsing and chain verification |

#### Incident Response
| Directory | Purpose |
|-----------|---------|
| `ioc-extract/` | IOC (Indicator of Compromise) extraction |
| `malware-hash/` | Malware hash reputation lookup — VirusTotal |
| `log-analysis/` | Security log analysis and anomaly detection |

#### Compliance
| Directory | Purpose |
|-----------|---------|
| `owasp-check/` | OWASP Top 10 checklist review |
| `isms-checklist/` | ISMS-P certification item review |

### Infrastructure
| Directory | Purpose |
|-----------|---------|
| `scripts/` | Validation and utility scripts (see `scripts/AGENTS.md`) |
| `docs/` | Installation and contribution documentation (see `docs/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Skill directories are placed flat at the root — no nesting
- Each skill directory contains only one `SKILL.md`
- Execution is delegated to existing security tools; do not include source code inside skills
- When adding a new skill, refer to `docs/contributing.md`

### Testing Requirements
```bash
./scripts/validate-skills.sh   # Structure validation
npm test                       # Documentation convention tests
```

### Common Patterns
- SKILL.md YAML frontmatter: `name`, `description`, `license`, `metadata.category`
- Credential resolution order: environment variables → `~/.config/security-skill/secrets.env` → query user
- Environment variable prefix: `SECSKILL_`

## Dependencies

### External
- Node.js >= 18 (for running validation scripts)
- Go toolchain (for installing subfinder, nuclei, httpx, trufflehog)
- Python 3 (pip-audit, holehe, hashid, wafw00f, etc.)
- System packages: nmap, whois, dnsutils, openssl, jq, curl

<!-- MANUAL: -->
