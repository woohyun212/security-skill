<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-13 | Updated: 2026-04-13 -->

# scripts

## Purpose
A collection of utility scripts for skill validation and CI.

## Key Files

| File | Description |
|------|-------------|
| `validate-skills.sh` | Validates the SKILL.md structure in all skill directories (frontmatter, name match, etc.) |
| `skill-docs.test.js` | Tests SKILL.md documentation conventions (required sections, category validity) |

## For AI Agents

### Working In This Directory
- `validate-skills.sh` iterates over all skill directories from the root and validates them
- `skill-docs.test.js` is executed with `node scripts/skill-docs.test.js`
- When adding new validation rules, both files must be updated

### Testing Requirements
```bash
./scripts/validate-skills.sh
node scripts/skill-docs.test.js
```

## Dependencies

### Internal
- All skill directories at the root (`*/SKILL.md`)

### External
- bash (validate-skills.sh)
- Node.js >= 18 (skill-docs.test.js)

<!-- MANUAL: -->
