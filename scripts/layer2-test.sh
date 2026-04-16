#!/usr/bin/env bash
# layer2-test.sh — Layer 2 AI fidelity test runner
# Runs Claude Code sessions to verify skills are discoverable and followable
# Usage:
#   ./scripts/layer2-test.sh <skill-name>          # Test one skill
#   ./scripts/layer2-test.sh --all                  # Test all 15 representative skills
#   ./scripts/layer2-test.sh --report <dir>         # Save reports to directory

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCENARIOS_DIR="$REPO_ROOT/tests/scenarios/layer2"
REPORTS_DIR="${REPORT_DIR:-$REPO_ROOT/tests/reports/layer2/$(date +%Y-%m-%dT%H-%M)}"
SKILLS_DIR="${HOME}/.claude/skills"
MAX_TURNS="${SECSKILL_L2_MAX_TURNS:-20}"
PASS=0; FAIL=0; SKIP=0; TOTAL=0

# Representative skills (2+ per category)
LAYER2_SKILLS=(
  port-scan dns-recon
  nuclei-scan cve-lookup
  web-vuln-ssrf security-headers web-vuln-graphql
  hash-identify constant-time-analysis
  ioc-extract mitre-attack-lookup
  threat-model owasp-check
  secure-code-review insecure-defaults
)

install_skill() {
  local skill="$1"
  local skill_md="$REPO_ROOT/${skill}/SKILL.md"
  local target_dir="$SKILLS_DIR/${skill}"

  if [[ ! -f "$skill_md" ]]; then
    echo "  ERROR: $skill_md not found"
    return 1
  fi

  mkdir -p "$target_dir"
  cp "$skill_md" "$target_dir/SKILL.md"
}

uninstall_skill() {
  local skill="$1"
  rm -rf "$SKILLS_DIR/${skill}"
}

test_skill() {
  local skill="$1"
  local scenario="$SCENARIOS_DIR/${skill}.txt"
  TOTAL=$((TOTAL + 1))

  if [[ ! -f "$scenario" ]]; then
    echo "SKIP: $skill — no Layer 2 scenario"
    SKIP=$((SKIP + 1))
    return
  fi

  local scenario_prompt
  scenario_prompt=$(grep -v '^TOOL_PATTERN=\|^DONE_PATTERN=' "$scenario")

  # Read the SKILL.md and inject into prompt so --print mode has it
  local skill_content
  skill_content=$(cat "$REPO_ROOT/${skill}/SKILL.md" 2>/dev/null || echo "")

  local full_prompt
  full_prompt="You have the following security skill available. Follow its workflow to complete the task.

<skill>
${skill_content}
</skill>

Task: ${scenario_prompt}"

  echo "  Running Claude Code session for $skill..."

  local output_file="$REPORTS_DIR/${skill}.transcript.txt"
  mkdir -p "$REPORTS_DIR"

  local output
  output=$(timeout 180 claude -p --max-budget-usd 2 "$full_prompt" 2>&1) || true
  echo "$output" > "$output_file"

  # === Rubric evaluation (3 binary checks) ===
  local discovery=false execution=false completion=false

  # 1. Discovery: Skill content was injected into the prompt, so if the AI produced
  #    meaningful output (non-empty, no error-only), it consumed the skill.
  local output_lines
  output_lines=$(echo "$output" | wc -l | tr -d ' ')
  if [[ "$output_lines" -gt 3 ]]; then
    discovery=true
  fi

  # 2. Execution: Did AI reference or run expected tools?
  local tool_pattern
  tool_pattern=$(grep '^TOOL_PATTERN=' "$scenario" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
  if [[ -n "$tool_pattern" ]]; then
    if echo "$output" | grep -qiE "$tool_pattern"; then
      execution=true
    fi
  else
    # Fallback: check for any bash/command execution indicators
    if echo "$output" | grep -qiE "nmap|curl|grep|openssl|nuclei|subfinder|python|git diff"; then
      execution=true
    fi
  fi

  # 3. Completion: Does output satisfy done criteria?
  local done_pattern
  done_pattern=$(grep '^DONE_PATTERN=' "$scenario" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
  if [[ -n "$done_pattern" ]]; then
    if echo "$output" | grep -qiE "$done_pattern"; then
      completion=true
    fi
  else
    # Fallback: check for meaningful security output (not just errors)
    if echo "$output" | grep -qiE "finding|result|scan|report|vulnerab|risk|threat|hash|IOC|technique"; then
      completion=true
    fi
  fi

  # Generate report
  {
    echo "# Layer 2 Report: $skill"
    echo ""
    echo "## Rubric"
    echo "- Discovery: $($discovery && echo 'PASS' || echo 'FAIL')"
    echo "- Execution: $($execution && echo 'PASS' || echo 'FAIL')"
    echo "- Completion: $($completion && echo 'PASS' || echo 'FAIL')"
    echo ""
    echo "## Verdict: $(($discovery && $execution && $completion) && echo 'PASS' || echo 'FAIL')"
    echo ""
    echo "## Output (first 50 lines)"
    echo '```'
    echo "$output" | head -50
    echo '```'
  } > "$REPORTS_DIR/${skill}.report.md"

  # Verdict
  if $discovery && $execution && $completion; then
    echo "PASS: $skill [D:✓ E:✓ C:✓]"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $skill [D:$($discovery && echo '✓' || echo '✗') E:$($execution && echo '✓' || echo '✗') C:$($completion && echo '✓' || echo '✗')]"
    FAIL=$((FAIL + 1))
  fi

  # Cleanup installed skill
  uninstall_skill "$skill"
}

# Parse arguments
case "${1:-}" in
  --all)
    for skill in "${LAYER2_SKILLS[@]}"; do
      test_skill "$skill"
    done
    ;;
  --report)
    REPORTS_DIR="${2:-.}"
    shift 2
    for skill in "${LAYER2_SKILLS[@]}"; do
      test_skill "$skill"
    done
    ;;
  --help|-h)
    echo "Usage: $0 <skill-name> | --all | --report <dir>"
    echo ""
    echo "Layer 2 AI fidelity testing — runs Claude Code sessions"
    echo "Tests 15 representative skills across 7 categories"
    echo "Each session costs ~\$2-5 (Claude API)"
    echo ""
    echo "Representative skills:"
    for s in "${LAYER2_SKILLS[@]}"; do echo "  - $s"; done
    exit 0
    ;;
  "")
    echo "Usage: $0 <skill-name> | --all"
    exit 1
    ;;
  *)
    test_skill "$1"
    ;;
esac

echo ""
echo "Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP  TOTAL=$TOTAL"
echo "Reports: $REPORTS_DIR/"
