#!/usr/bin/env bash
# extract-commands.sh — Extract executable bash blocks from a SKILL.md Workflow section
# Usage: ./scripts/extract-commands.sh <path/to/SKILL.md> [path/to/vars.env]

set -euo pipefail

SKILL_FILE="${1:-}"
ENV_FILE="${2:-}"

if [[ -z "$SKILL_FILE" ]]; then
  echo "Usage: $0 <path/to/SKILL.md> [path/to/vars.env]" >&2
  exit 1
fi

if [[ ! -f "$SKILL_FILE" ]]; then
  echo "Error: SKILL.md not found: $SKILL_FILE" >&2
  exit 1
fi

if [[ -n "$ENV_FILE" && ! -f "$ENV_FILE" ]]; then
  echo "Error: env file not found: $ENV_FILE" >&2
  exit 1
fi

# Build substitution map from env file (only SECSKILL_* variables)
declare -A ENV_VARS=()
if [[ -n "$ENV_FILE" ]]; then
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    # Skip blank lines and comments
    [[ -z "$key" || "$key" == \#* ]] && continue
    # Strip leading/trailing whitespace from key
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    # Only capture SECSKILL_* variables
    if [[ "$key" == SECSKILL_* ]]; then
      # Strip surrounding quotes from value
      value="${value#\"}"
      value="${value%\"}"
      value="${value#\'}"
      value="${value%\'}"
      ENV_VARS["$key"]="$value"
    fi
  done < "$ENV_FILE"
fi

# Return number of keys in ENV_VARS safely (works under set -u)
env_var_count() {
  echo "${#ENV_VARS[@]}"
}

# Substitute SECSKILL_* variables in a line
substitute_vars() {
  local line="$1"
  local key
  # Iterate safely; if array is empty the loop body never runs
  for key in "${!ENV_VARS[@]}"; do
    local val="${ENV_VARS[$key]}"
    line="${line//\$$key/$val}"
    line="${line//\$\{$key\}/$val}"
    line="${line//\$\{$key:?*\}/$val}"
    line="${line//\$\{$key:-*\}/$val}"
  done
  echo "$line"
}

# --- Pre-compiled regex patterns ---
re_h2_any='^## '
re_h2_workflow='^## Workflow'
re_h3='^### '
re_fence_open='^```bash'
re_fence_close='^```'

# --- Parser state ---
in_workflow=0
in_block=0
skip_block=0
current_step=""
block_lines=()
header_emitted=0

# Flush the current block to stdout
flush_block() {
  local step="$1"
  local i

  # Emit header once
  if [[ $header_emitted -eq 0 ]]; then
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf '# Extracted from: %s\n' "$SKILL_FILE"
    printf '\n'
    header_emitted=1
  fi

  # Emit step comment
  if [[ -n "$step" ]]; then
    printf '# %s\n' "$step"
  fi

  # Emit lines
  local has_env
  has_env=$(env_var_count)
  for (( i=0; i<${#block_lines[@]}; i++ )); do
    if [[ "$has_env" -gt 0 ]]; then
      substitute_vars "${block_lines[$i]}"
    else
      printf '%s\n' "${block_lines[$i]}"
    fi
  done
  printf '\n'
}

while IFS= read -r line || [[ -n "$line" ]]; do

  # --- Section boundary detection ---
  if [[ "$line" =~ $re_h2_any ]]; then
    if [[ "$line" =~ $re_h2_workflow ]]; then
      in_workflow=1
      in_block=0
      skip_block=0
      block_lines=()
      continue
    else
      [[ $in_workflow -eq 1 ]] && in_workflow=0
    fi
  fi

  [[ $in_workflow -eq 0 ]] && continue

  # --- Step heading (### inside Workflow) ---
  if [[ "$line" =~ $re_h3 ]]; then
    # Use the raw heading text as the step label (no extra "Step N:" prefix)
    current_step="${line#'### '}"
    continue
  fi

  # --- Code fence open ---
  if [[ "$line" =~ $re_fence_open ]]; then
    in_block=1
    skip_block=0
    block_lines=()
    continue
  fi

  # --- Code fence close ---
  if [[ "$line" =~ $re_fence_close && $in_block -eq 1 ]]; then
    in_block=0
    if [[ $skip_block -eq 0 && ${#block_lines[@]} -gt 0 ]]; then
      flush_block "$current_step"
      current_step=""
    fi
    skip_block=0
    block_lines=()
    continue
  fi

  # --- Inside a code block ---
  if [[ $in_block -eq 1 ]]; then
    # Mark block for skipping if any skip-marker comment is present
    if [[ "$line" == *'# Example output'* || "$line" == *'# Optional'* || "$line" == *'# test:skip'* ]]; then
      skip_block=1
    fi
    block_lines+=("$line")
  fi

done < "$SKILL_FILE"
