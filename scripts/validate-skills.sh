#!/usr/bin/env bash
set -euo pipefail

# validate-skills.sh — 모든 스킬 디렉토리의 SKILL.md 유효성 검증

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKIP_DIRS=".git .github .omc docs scripts packages python-packages node_modules"
errors=0
checked=0

for dir in "$REPO_ROOT"/*/; do
  dirname="$(basename "$dir")"

  # 스킬이 아닌 디렉토리 건너뛰기
  skip=false
  for s in $SKIP_DIRS; do
    [ "$dirname" = "$s" ] && skip=true && break
  done
  $skip && continue

  skill_file="$dir/SKILL.md"
  checked=$((checked + 1))

  # SKILL.md 존재 여부
  if [ ! -f "$skill_file" ]; then
    echo "ERROR: $dirname/ — SKILL.md not found"
    errors=$((errors + 1))
    continue
  fi

  # 허용된 파일만 존재하는지 확인 (SKILL.md + optional REFERENCE.md)
  for f in "$dir"/*; do
    fname="$(basename "$f")"
    if [ "$fname" != "SKILL.md" ] && [ "$fname" != "REFERENCE.md" ]; then
      echo "WARN: $dirname/ — unexpected file '$fname' (only SKILL.md and REFERENCE.md allowed)"
    fi
  done

  # SKILL.md 라인 수 경고
  line_count="$(wc -l < "$skill_file")"
  if [ "$line_count" -gt 400 ]; then
    echo "WARN: $dirname/SKILL.md — $line_count lines (recommended: ≤400). Consider extracting to REFERENCE.md"
  fi

  # YAML 프론트매터 시작 여부
  first_line="$(head -n 1 "$skill_file")"
  if [ "$first_line" != "---" ]; then
    echo "ERROR: $dirname/SKILL.md — missing YAML frontmatter (first line must be '---')"
    errors=$((errors + 1))
    continue
  fi

  # name 필드 존재 및 디렉토리명 일치
  name_line="$(grep -m 1 '^name:' "$skill_file" || true)"
  if [ -z "$name_line" ]; then
    echo "ERROR: $dirname/SKILL.md — missing 'name:' field in frontmatter"
    errors=$((errors + 1))
  else
    name_value="$(echo "$name_line" | sed 's/^name:[[:space:]]*//')"
    if [ "$name_value" != "$dirname" ]; then
      echo "ERROR: $dirname/SKILL.md — name '$name_value' does not match directory '$dirname'"
      errors=$((errors + 1))
    fi
  fi

  # description 필드 존재
  desc_line="$(grep -m 1 '^description:' "$skill_file" || true)"
  if [ -z "$desc_line" ]; then
    echo "ERROR: $dirname/SKILL.md — missing 'description:' field in frontmatter"
    errors=$((errors + 1))
  fi
done

echo ""
echo "Checked $checked skill(s), found $errors error(s)."
[ "$errors" -eq 0 ] && echo "All skills valid." && exit 0
exit 1
