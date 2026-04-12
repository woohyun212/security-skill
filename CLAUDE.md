# security-skill 개발 규칙

## 프로젝트 개요
AI 에이전트용 보안 스킬 모음집. 각 스킬은 `<skill-name>/SKILL.md` 형태의 마크다운 지시서.

## 스킬 규칙
- 스킬 디렉토리는 루트에 flat하게 배치 (중첩 금지)
- 각 스킬 디렉토리에는 `SKILL.md` 하나만 존재
- `SKILL.md`의 `name:` 프론트매터는 디렉토리 이름과 반드시 일치
- 스킬은 기존 보안 도구(nmap, nuclei, subfinder 등)에 실행을 위임
- 스킬 자체에 실행 가능한 소스코드를 포함하지 않음

## SKILL.md 프론트매터 필수 필드
```yaml
name: <directory-name>
description: <영문 한 줄 설명>
license: MIT
metadata:
  category: <recon|vuln-analysis|web-security|crypto|incident-response|compliance|code-security>
  locale: ko-KR
  phase: v1
```

## 보안 원칙
- 모든 스킬은 합법적 보안 테스트/방어 목적만 다룸
- 스킬에 공격 자동화 코드를 포함하지 않음 — 도구 사용 지시만 제공
- 인증이 필요한 외부 API는 환경변수로 크리덴셜 관리
- 크리덴셜 해결 순서: 환경변수 → `~/.config/security-skill/secrets.env` → 사용자에게 질의

## 검증
```bash
./scripts/validate-skills.sh   # 모든 스킬 구조 검증
npm test                       # 문서 컨벤션 테스트
```

## 디렉토리 구조
- `<skill-name>/SKILL.md` — 스킬 정의
- `scripts/` — 검증 및 유틸리티
- `docs/` — 문서
- `packages/` — 향후 npm 패키지
