#!/usr/bin/env bash
# layer1-test.sh — Layer 1 deterministic test runner for security skill verification
# Usage:
#   ./scripts/layer1-test.sh <skill>              # Test one skill
#   ./scripts/layer1-test.sh --all                # Test all skills with scenario files
#   ./scripts/layer1-test.sh --category recon     # Test skills in a category
#   ./scripts/layer1-test.sh --report <dir>       # Write reports to <dir>
#   ./scripts/layer1-test.sh --summary            # Print PASS/FAIL/SKIP totals (default: always printed)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCENARIOS_DIR="$REPO_ROOT/tests/scenarios"
REPORTS_DIR="${REPORT_DIR:-$REPO_ROOT/tests/reports/$(date +%Y-%m-%dT%H-%M)}"

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ── helpers ────────────────────────────────────────────────────────────────────

usage() {
  cat >&2 <<EOF
Usage:
  $(basename "$0") <skill>
  $(basename "$0") --all
  $(basename "$0") --category <category>
  $(basename "$0") --report <dir>   (can be combined with any run mode)
  $(basename "$0") --summary        (summary is always printed; flag is a no-op kept for compatibility)

Options:
  --all              Run all skills that have scenario files in tests/scenarios/
  --category <cat>   Run only skills whose SKILL.md metadata.category matches <cat>
  --report <dir>     Override the reports output directory
  --summary          Print PASS/FAIL/SKIP totals (always printed; provided for scripting convenience)
EOF
  exit 1
}

# Return the category value from a SKILL.md frontmatter block
skill_category() {
  local skill_md="$1"
  grep -m1 'category:' "$skill_md" 2>/dev/null | sed 's/.*category:[[:space:]]*//' | tr -d '\r' || true
}

# ── core test function ─────────────────────────────────────────────────────────

test_skill() {
  local skill="$1"
  local env_file="$SCENARIOS_DIR/${skill}.env"
  local expected_file="$SCENARIOS_DIR/${skill}.expected"
  local skill_md="$REPO_ROOT/${skill}/SKILL.md"

  TOTAL=$((TOTAL + 1))

  # Missing scenario files → SKIP
  if [[ ! -f "$env_file" || ! -f "$expected_file" ]]; then
    echo "SKIP: $skill — no scenario files"
    SKIP=$((SKIP + 1))
    return
  fi

  # Missing SKILL.md → SKIP
  if [[ ! -f "$skill_md" ]]; then
    echo "SKIP: $skill — SKILL.md not found"
    SKIP=$((SKIP + 1))
    return
  fi

  # Source env variables into current shell so extract-commands can substitute them
  # shellcheck disable=SC1090
  set +u
  source "$env_file"
  set -u

  # Extract substituted commands and execute them; capture combined stdout+stderr
  # If SECSKILL_INPUT points to a file and skill reads from stdin, pipe it in
  local output
  local stdin_file=""
  if [[ -n "${SECSKILL_INPUT:-}" ]] && [[ -f "${SECSKILL_INPUT:-}" ]]; then
    stdin_file="$SECSKILL_INPUT"
  fi

  local skill_timeout="${SECSKILL_TIMEOUT:-120}"

  if [[ -n "$stdin_file" ]]; then
    output=$(
      timeout "$skill_timeout" bash -c "$("$REPO_ROOT/scripts/extract-commands.sh" "$skill_md" "$env_file" 2>&1)" 2>&1 < "$stdin_file"
    ) || true
  else
    output=$(
      timeout "$skill_timeout" bash -c "$("$REPO_ROOT/scripts/extract-commands.sh" "$skill_md" "$env_file" 2>&1)" 2>&1
    ) || true
  fi

  # Load expected patterns into an isolated subshell to avoid polluting current env,
  # then export each PATTERN_* / ANTIPATTERN_* we find.
  # We read them back via process substitution.
  local pass=true
  local pattern_failures=()
  local antipattern_failures=()

  # Collect variable names from the expected file
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    # Strip whitespace
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ -z "$key" ]] && continue

    # Strip surrounding quotes from value
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"

    if [[ "$key" == PATTERN_* ]]; then
      if ! echo "$output" | grep -qE "$value"; then
        pattern_failures+=("$key: '$value'")
        pass=false
      fi
    elif [[ "$key" == ANTIPATTERN_* ]]; then
      if echo "$output" | grep -qE "$value"; then
        antipattern_failures+=("$key: '$value'")
        pass=false
      fi
    fi
  done < "$expected_file"

  # Print per-failure details before the verdict line
  for msg in "${pattern_failures[@]+"${pattern_failures[@]}"}"; do
    echo "  FAIL pattern not found — $msg"
  done
  for msg in "${antipattern_failures[@]+"${antipattern_failures[@]}"}"; do
    echo "  FAIL antipattern matched — $msg"
  done

  if $pass; then
    echo "PASS: $skill"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $skill"
    FAIL=$((FAIL + 1))
  fi

  # Save report
  mkdir -p "$REPORTS_DIR"
  {
    echo "=== $skill (Layer 1) ==="
    echo "Verdict: $( $pass && echo PASS || echo FAIL )"
    echo ""
    echo "Output (truncated to 50 lines):"
    echo "$output" | head -50
  } > "$REPORTS_DIR/${skill}.txt"
}

# ── collect skills by category ─────────────────────────────────────────────────

skills_in_category() {
  local category="$1"
  local found=()
  for env_file in "$SCENARIOS_DIR"/*.env; do
    [[ -f "$env_file" ]] || continue
    local skill
    skill="$(basename "$env_file" .env)"
    local skill_md="$REPO_ROOT/${skill}/SKILL.md"
    if [[ -f "$skill_md" ]]; then
      local cat
      cat="$(skill_category "$skill_md")"
      if [[ "$cat" == "$category" ]]; then
        found+=("$skill")
      fi
    fi
  done
  printf '%s\n' "${found[@]+"${found[@]}"}"
}

# ── argument parsing ───────────────────────────────────────────────────────────

MODE=""         # single | all | category
TARGET_SKILL=""
TARGET_CATEGORY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      MODE="all"
      shift
      ;;
    --category)
      [[ $# -lt 2 ]] && { echo "Error: --category requires an argument" >&2; usage; }
      MODE="category"
      TARGET_CATEGORY="$2"
      shift 2
      ;;
    --report)
      [[ $# -lt 2 ]] && { echo "Error: --report requires an argument" >&2; usage; }
      REPORTS_DIR="$2"
      shift 2
      ;;
    --summary)
      # no-op: summary is always printed
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "Error: unknown option '$1'" >&2
      usage
      ;;
    *)
      if [[ -z "$MODE" ]]; then
        MODE="single"
        TARGET_SKILL="$1"
      else
        echo "Error: unexpected argument '$1'" >&2
        usage
      fi
      shift
      ;;
  esac
done

[[ -z "$MODE" ]] && usage

# ── dispatch ───────────────────────────────────────────────────────────────────

case "$MODE" in
  single)
    test_skill "$TARGET_SKILL"
    ;;
  all)
    for env_file in "$SCENARIOS_DIR"/*.env; do
      [[ -f "$env_file" ]] || continue
      skill="$(basename "$env_file" .env)"
      test_skill "$skill"
    done
    ;;
  category)
    mapfile -t skills < <(skills_in_category "$TARGET_CATEGORY")
    if [[ ${#skills[@]} -eq 0 ]]; then
      echo "No skills found for category '$TARGET_CATEGORY'"
    else
      for skill in "${skills[@]}"; do
        test_skill "$skill"
      done
    fi
    ;;
esac

# ── summary ────────────────────────────────────────────────────────────────────

echo ""
echo "Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  TOTAL=$TOTAL"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
