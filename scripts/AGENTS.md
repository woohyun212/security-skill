<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-13 | Updated: 2026-04-13 -->

# scripts

## Purpose
스킬 유효성 검증 및 CI용 유틸리티 스크립트 모음.

## Key Files

| File | Description |
|------|-------------|
| `validate-skills.sh` | 모든 스킬 디렉토리의 SKILL.md 구조 검증 (프론트매터, name 일치 등) |
| `skill-docs.test.js` | SKILL.md 문서 컨벤션 테스트 (필수 섹션, 카테고리 유효성) |

## For AI Agents

### Working In This Directory
- `validate-skills.sh`는 루트에서 모든 스킬 디렉토리를 순회하며 검증
- `skill-docs.test.js`는 `node scripts/skill-docs.test.js`로 실행
- 새 검증 규칙 추가 시 두 파일 모두 업데이트 필요

### Testing Requirements
```bash
./scripts/validate-skills.sh
node scripts/skill-docs.test.js
```

## Dependencies

### Internal
- 루트의 모든 스킬 디렉토리 (`*/SKILL.md`)

### External
- bash (validate-skills.sh)
- Node.js >= 18 (skill-docs.test.js)

<!-- MANUAL: -->
