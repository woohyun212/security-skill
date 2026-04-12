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

## Skill List

### Recon
| Skill | Description |
|-------|-------------|
| [`subdomain-enum`](subdomain-enum/) | Subdomain enumeration (subfinder, amass) |
| [`dns-recon`](dns-recon/) | DNS record reconnaissance and zone transfer attempts |
| [`whois-lookup`](whois-lookup/) | Domain/IP WHOIS lookup |
| [`port-scan`](port-scan/) | Port scanning and service detection (nmap) |
| [`cert-transparency`](cert-transparency/) | Certificate Transparency log lookup |
| [`osint-email`](osint-email/) | Email address-based OSINT collection |

### Vulnerability Analysis
| Skill | Description |
|-------|-------------|
| [`cve-lookup`](cve-lookup/) | CVE detailed information lookup (NVD/MITRE) |
| [`nuclei-scan`](nuclei-scan/) | Nuclei template-based vulnerability scanning |
| [`dependency-audit`](dependency-audit/) | Dependency vulnerability audit (npm audit, pip-audit, trivy) |
| [`secret-scan`](secret-scan/) | Secret/credential detection in source code |

### Web Security
| Skill | Description |
|-------|-------------|
| [`security-headers`](security-headers/) | HTTP security header analysis |
| [`ssl-check`](ssl-check/) | SSL/TLS certificate and configuration check |
| [`cors-check`](cors-check/) | CORS misconfiguration detection |
| [`waf-detect`](waf-detect/) | Web Application Firewall (WAF) detection |

### Cryptography
| Skill | Description |
|-------|-------------|
| [`hash-identify`](hash-identify/) | Hash type identification and verification |
| [`encoding-toolkit`](encoding-toolkit/) | Encoding/decoding conversion (Base64, URL, Hex, etc.) |
| [`cert-parse`](cert-parse/) | X.509 certificate parsing and chain validation |

### Incident Response
| Skill | Description |
|-------|-------------|
| [`ioc-extract`](ioc-extract/) | IOC (Indicator of Compromise) extraction from text |
| [`malware-hash`](malware-hash/) | Malware hash reputation lookup (VirusTotal) |
| [`log-analysis`](log-analysis/) | Security log analysis and anomaly detection |

### Compliance
| Skill | Description |
|-------|-------------|
| [`owasp-check`](owasp-check/) | OWASP Top 10 checklist-based assessment |
| [`isms-checklist`](isms-checklist/) | ISMS-P certification item checklist |

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

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions from the security community are welcome. New skill PRs, improvements to existing skills, and bug reports are all appreciated.
