# Skill Contribution Guide

## How to Write a New Skill

### 1. Create the Directory

```bash
mkdir <skill-name>
```

- Use lowercase letters with hyphens (e.g., `sql-inject-check`)
- Place flat at the root

### 2. Write SKILL.md

Create only one `<skill-name>/SKILL.md` file.

```markdown
---
name: <skill-name>
description: One-line English description for agent discovery
license: MIT
metadata:
  category: <recon|vuln-analysis|web-security|crypto|incident-response|compliance|code-security>
  locale: ko-KR
  phase: v1
---

# Skill Title

## What this skill does
Description of what this skill does

## When to use
- Situation 1 where this skill should be used
- Situation 2 where this skill should be used

## When not to use
- Situations where this skill should not be used

## Prerequisites
- List of required tools/packages

## Required environment variables
(Only if authentication is needed)

## Inputs
Information to collect from the user

## Workflow
### 1. First step
\`\`\`bash
command
\`\`\`

### 2. Second step
\`\`\`bash
command
\`\`\`

## Done when
- Completion condition 1
- Completion condition 2

## Failure modes
- Failure cases and how to handle them

## Notes
- Additional reference notes
```

### 3. Validate

```bash
./scripts/validate-skills.sh
npm test
```

### 4. Submit a PR

- Branch: `skill/<skill-name>`
- PR title: `feat(skill): add <skill-name>`
- One PR per skill

## Categories

| Category | Description |
|----------|-------------|
| `recon` | Reconnaissance and OSINT |
| `vuln-analysis` | Vulnerability analysis |
| `web-security` | Web application security |
| `crypto` | Cryptography |
| `incident-response` | Incident response |
| `compliance` | Compliance and auditing |
| `code-security` | Source code security |

## Principles

1. **Legitimate purposes only** — all skills are for defensive/testing purposes
2. **Delegate to tools** — skills are instruction files, no executable code
3. **English frontmatter** — body content may be in any language, but the frontmatter `description` must be in English
4. **Practical** — must be immediately usable in real-world workflows
