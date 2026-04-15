# Skill Verification Testing Guide

## Overview

Two-layer testing validates all 58 security skills produce correct output when followed:

- **Layer 1 (Deterministic)**: Bash commands execute against Docker targets. Test correctness.
- **Layer 2 (AI Fidelity)**: Claude Code sessions test real-world discoverability. Test usability.

Skills are classified into 4 tiers based on testability. Layer 1 covers Tier 1 (30 skills); Layer 2 covers 15 representative skills across all categories.

## Prerequisites

```bash
# 1. Install Docker + Docker Compose
docker --version && docker-compose --version

# 2. Check required security tools
./scripts/check-tools.sh

# 3. Required tools (via apt, brew, or manual):
# nmap nuclei dig curl openssl subfinder wafw00f trufflehog gitleaks
# trivy syft sigma-cli python3 git jq
```

## Quick Start

```bash
# Start Docker test environment (9 containers)
cd tests/docker && docker-compose up -d

# Verify all containers are running
docker ps | grep -E "dvwa|juice-shop|nginx|graphql|ssti|dns|git|api|log"

# Run a single skill test
./scripts/layer1-test.sh port-scan

# Run all Tier 1 tests (30 skills)
./scripts/layer1-test.sh --tier 1

# View reports
cat tests/reports/2026-04-15/summary.md
```

## Tier Classification

| Tier | Count | What | How | Layer |
|------|-------|------|-----|-------|
| **1** | 30 | Tool-against-Docker targets | Deterministic bash execution | Layer 1 |
| **2** | 16 | Real-world targets, methodology | Claude Code sessions | Layer 2 |
| **3** | 6 | Interactive input (`read -rp`) | Fix env vars first, then Tier 1/2 | — |
| **4** | 11 | Requires cloud/AD/mobile infra | Manual verification only | — |

### Tier 1 Skills (Layer 1 deterministic)

**Recon** (5): port-scan, dns-recon, subdomain-enum, cert-transparency, whois-lookup  
**Vuln-analysis** (5): nuclei-scan, dependency-audit, secret-scan, supply-chain-audit, cve-lookup  
**Web-security** (11): security-headers, ssl-check, cors-check, waf-detect, web-vuln-* (6), web-vuln-graphql, web-vuln-cache-poisoning  
**Crypto** (3): hash-identify, encoding-toolkit, cert-parse  
**Incident-response** (4): ioc-extract, mitre-attack-lookup, log-analysis*, malware-hash*  
**Code-security** (2): differential-review, insecure-defaults  

*After Tier 3 fix: env var fallback instead of `read -rp`

### Tier 2 Skills (Layer 2 AI sessions)

**Compliance** (6): owasp-check, isms-checklist, threat-model, pentest-report, bug-bounty-validation, spec-to-code-compliance  
**Web-security** (5): bug-bounty-methodology, web-vuln-oauth, web-vuln-mfa-bypass, web-vuln-saml-sso, exploit-chain-building  
**Code-security** (2): secure-code-review, devsecops-pipeline  
**Other** (3): siem-rule, constant-time-analysis, web-vuln-business-logic

## Test Scenarios

Each Tier 1 skill has two test files:

```bash
tests/scenarios/port-scan.env       # Input vars: SECSKILL_TARGET=dvwa, SECSKILL_PORTS=80,443
tests/scenarios/port-scan.expected  # Output patterns (regex) + antipatterns to match/reject
```

### Example: port-scan test

```bash
# .env: Set target and parameters
SECSKILL_TARGET=dvwa
SECSKILL_PORTS=80,443

# .expected: Verify output
PATTERN_1="80/tcp.*open"
PATTERN_2="Apache|nginx|httpd"
ANTIPATTERN_1="filtered|closed"  # Port 80 must be open
```

## Running Tests

### Single skill
```bash
./scripts/layer1-test.sh port-scan
# Output: PASS or FAIL with specific pattern details
```

### All Tier 1
```bash
./scripts/layer1-test.sh --tier 1
# Runs 30 skills, generates reports/
```

### One category
```bash
./scripts/layer1-test.sh --category recon
```

### Tier 2 (AI fidelity) - Representative 15 skills
```bash
# Manually: Install skill, launch Claude Code session, evaluate rubric
cp port-scan/SKILL.md ~/.claude/skills/port-scan/SKILL.md
claude --print --output-format stream-json --max-turns 30 "Your prompt here"
# Check: Did AI read SKILL.md? Did it run expected tools? Did it complete the task?
```

## Interpreting Results

### Layer 1 Report Format

```
=== port-scan (Layer 1) ===
Verdict: PASS
Duration: 12s
Commands executed: 2
  [1] nmap -sV -sC dvwa → exit 0 ✓
  [2] grep '80/tcp' → match ✓
Patterns: 2/2 matched, 0 anti-patterns triggered
```

**PASS**: All patterns matched, no anti-patterns fired  
**FAIL**: Missing pattern or anti-pattern matched (shows which one)  
**SKIP**: No scenario files for this skill

### Layer 2 Rubric (3 binary checks)

Each AI session is evaluated on:

1. **Discovery**: AI read the correct SKILL.md file
2. **Execution**: AI ran at least one expected tool command (nmap, nuclei, dig, etc.)
3. **Completion**: Output satisfies the skill's "Done when" criteria

All three must pass for PASS verdict.

## Adding a New Skill Test

```bash
# 1. Create scenario env file
cat > tests/scenarios/new-skill.env << EOF
SECSKILL_TARGET=dvwa
SECSKILL_OPTION=value
EOF

# 2. Create expected patterns
cat > tests/scenarios/new-skill.expected << EOF
PATTERN_1="expected regex output"
ANTIPATTERN_1="should not appear"
EOF

# 3. Run test
./scripts/layer1-test.sh new-skill
```

## Docker Targets

| Container | Port | Skills tested |
|-----------|------|---------------|
| dvwa | 80 | port-scan, nuclei-scan, web-vuln-idor |
| juice-shop | 3000 | web-vuln-ssrf, cors-check |
| nginx-misconfig | 8080 | security-headers, ssl-check |
| graphql-dvga | 5000 | web-vuln-graphql |
| ssti-app | 5001 | web-vuln-ssti |
| bind9 (DNS) | 53 | dns-recon, subdomain-enum |
| git-repo | — | secret-scan, dependency-audit |
| mock-api | 8000 | cve-lookup, mitre-attack-lookup |
| log-source | — | ioc-extract, log-analysis |

## Cleanup

```bash
# Stop and remove all containers
docker-compose -f tests/docker/docker-compose.yml down -v --remove-orphans

# Resume test run from failed skill
./scripts/layer1-test.sh port-scan
```

## Cost and Time

- **Layer 1**: ~15-30 minutes, near-zero cost (local Docker)
- **Layer 2**: ~3-4 hours, ~$50-75 (15 Claude Code sessions × ~$3-5 each)
- Run Layer 1 frequently; Layer 2 quarterly or before releases

## Full Plan Reference

See `.omc/plans/skill-verification-plan.md` for detailed architecture, tier classification rationale, and Tier 3/4 handling.
