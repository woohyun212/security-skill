# security-skill Development Rules

## Project Overview
A collection of security skills for AI agents. Each skill is a markdown instruction file in the form `<skill-name>/SKILL.md`.

## Skill Rules
- Skill directories are placed flat at the root (no nesting)
- Each skill directory contains `SKILL.md` and an optional `REFERENCE.md`
- `REFERENCE.md` holds lookup tables, templates, checklists, and other static reference data
- `SKILL.md` should stay under 400 lines — extract heavy reference material to `REFERENCE.md`
- The `name:` frontmatter in `SKILL.md` must match the directory name exactly
- Skills delegate execution to existing security tools (nmap, nuclei, subfinder, etc.)
- Skills must not contain executable source code

## SKILL.md Frontmatter Required Fields
```yaml
name: <directory-name>
description: <one-line English description>
license: MIT
metadata:
  category: <recon|vuln-analysis|web-security|crypto|incident-response|compliance|code-security>
  locale: ko-KR
  phase: v1
```

## Security Principles
- All skills cover only legitimate security testing/defensive purposes
- Skills must not contain attack automation code — provide tool usage instructions only
- Credentials for external APIs requiring authentication are managed via environment variables
- Credential resolution order: environment variables → `~/.config/security-skill/secrets.env` → query the user

## Validation
```bash
./scripts/validate-skills.sh   # Validate all skill structures
npm test                       # Documentation convention tests
```

## Directory Structure
- `<skill-name>/SKILL.md` — skill definition (workflow and instructions)
- `<skill-name>/REFERENCE.md` — optional reference data (tables, templates, checklists)
- `scripts/` — validation and utilities
- `docs/` — documentation
- `packages/` — future npm packages
