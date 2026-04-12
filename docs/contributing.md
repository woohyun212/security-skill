# 스킬 기여 가이드

## 새 스킬 작성법

### 1. 디렉토리 생성

```bash
mkdir <skill-name>
```

- 소문자, 하이픈 구분 (예: `sql-inject-check`)
- 루트에 flat하게 배치

### 2. SKILL.md 작성

`<skill-name>/SKILL.md` 파일 하나만 생성합니다.

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

# 스킬 한국어 제목

## What this skill does
이 스킬이 무엇을 하는지 설명

## When to use
- 이 스킬을 사용해야 하는 상황 1
- 이 스킬을 사용해야 하는 상황 2

## When not to use
- 이 스킬을 사용하면 안 되는 상황

## Prerequisites
- 필요한 도구/패키지 목록

## Required environment variables
(인증이 필요한 경우만)

## Inputs
사용자로부터 수집해야 할 정보

## Workflow
### 1. 첫 번째 단계
\`\`\`bash
명령어
\`\`\`

### 2. 두 번째 단계
\`\`\`bash
명령어
\`\`\`

## Done when
- 완료 조건 1
- 완료 조건 2

## Failure modes
- 실패 케이스 및 대응 방법

## Notes
- 추가 참고사항
```

### 3. 검증

```bash
./scripts/validate-skills.sh
npm test
```

### 4. PR 제출

- 브랜치: `skill/<skill-name>`
- PR 제목: `feat(skill): add <skill-name>`
- 스킬 하나당 PR 하나

## 카테고리

| 카테고리 | 설명 |
|----------|------|
| `recon` | 정찰 및 OSINT |
| `vuln-analysis` | 취약점 분석 |
| `web-security` | 웹 애플리케이션 보안 |
| `crypto` | 암호학 |
| `incident-response` | 침해 대응 |
| `compliance` | 컴플라이언스/감사 |
| `code-security` | 소스코드 보안 |

## 원칙

1. **합법적 목적만** — 모든 스킬은 방어/테스트 목적
2. **도구 위임** — 스킬은 지시서, 실행 코드 포함 금지
3. **한국어 우선** — 본문은 한국어, 프론트매터 description은 영문
4. **실용적** — 실제 업무에서 바로 쓸 수 있어야 함
