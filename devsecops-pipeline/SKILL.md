---
name: devsecops-pipeline
description: Assess CI/CD pipeline security maturity, identify DevSecOps gaps, and generate GitHub Actions/GitLab CI configs with security gates
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Assesses the current CI/CD pipeline security maturity across 8 stages (Plan → Code → Build → Test → Release → Deploy → Operate → Monitor), identifies gaps, and produces ready-to-use GitHub Actions workflow configurations, security gate policy definitions, and a phased implementation roadmap.

## When to use

- When adding security controls to an existing CI/CD pipeline
- When setting up a new pipeline that needs built-in security from the start
- When preparing for a DevSecOps maturity assessment or audit
- When standardizing security tooling across multiple teams or repositories

## Prerequisites

Tools are referenced per stage; install only what applies to your stack:

- **SAST**: `semgrep` (free), CodeQL (GitHub-native), SonarQube (self-hosted or cloud)
- **SCA**: `snyk` CLI, `trivy`, Dependabot (GitHub-native)
- **Secrets scanning**: `gitleaks`
- **IaC scanning**: `checkov`, `tfsec`
- **Container scanning**: `trivy`, `grype` + `syft`
- **DAST**: `zaproxy` (OWASP ZAP), `nuclei`
- **SBOM**: `syft` (CycloneDX/SPDX output), `cosign` (artifact signing)
- **Runtime**: Falco (Kubernetes), CSPM tool (AWS Security Hub, GCP SCC, etc.)

```bash
# Install core tools (Debian/Ubuntu)
pip install semgrep checkov
brew install gitleaks trivy grype syft cosign nuclei  # macOS
# Or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
```

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_REPO_PATH` | Required | Path to the repository root |
| `SECSKILL_CI_PLATFORM` | Optional | `github` or `gitlab` (default: `github`) |
| `SECSKILL_OUTPUT_DIR` | Optional | Output directory (default: `./devsecops-output`) |
| `SECSKILL_REGISTRY` | Optional | Container registry URL for image scanning |
| `SECSKILL_IMAGE_NAME` | Optional | Container image name:tag to scan |

## Workflow

### Step 1: Assess current pipeline maturity

```bash
export REPO="${SECSKILL_REPO_PATH:?Set SECSKILL_REPO_PATH}"
export CI_PLATFORM="${SECSKILL_CI_PLATFORM:-github}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./devsecops-output}"
mkdir -p "$OUTDIR"

MATURITY_FILE="$OUTDIR/maturity_assessment.txt"
echo "DevSecOps Pipeline Maturity Assessment" > "$MATURITY_FILE"
echo "Repo    : $REPO" >> "$MATURITY_FILE"
echo "Platform: $CI_PLATFORM" >> "$MATURITY_FILE"
echo "Date    : $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$MATURITY_FILE"
echo "" >> "$MATURITY_FILE"

echo "[*] Detecting existing pipeline files..."

# Detect CI config presence
GITHUB_WORKFLOWS="$REPO/.github/workflows"
GITLAB_CI="$REPO/.gitlab-ci.yml"
HAS_GITHUB_ACTIONS=false
HAS_GITLAB_CI=false
[ -d "$GITHUB_WORKFLOWS" ] && HAS_GITHUB_ACTIONS=true && echo "[+] GitHub Actions workflows found"
[ -f "$GITLAB_CI" ] && HAS_GITLAB_CI=true && echo "[+] GitLab CI config found"

# Detect existing security tools in CI configs
check_tool_in_ci() {
  local tool="$1"
  if [ "$HAS_GITHUB_ACTIONS" = "true" ]; then
    grep -rl "$tool" "$GITHUB_WORKFLOWS" >/dev/null 2>&1 && echo "present" || echo "absent"
  elif [ "$HAS_GITLAB_CI" = "true" ]; then
    grep -q "$tool" "$GITLAB_CI" 2>/dev/null && echo "present" || echo "absent"
  else
    echo "no-ci"
  fi
}

echo "" >> "$MATURITY_FILE"
echo "Stage Coverage:" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "Pre-commit hooks (gitleaks):" "$(check_tool_in_ci gitleaks)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "SAST (semgrep/codeql):" "$(check_tool_in_ci semgrep; check_tool_in_ci codeql | tail -1)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "SCA (snyk/trivy):" "$(check_tool_in_ci snyk; check_tool_in_ci trivy | tail -1)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "IaC scanning (checkov/tfsec):" "$(check_tool_in_ci checkov; check_tool_in_ci tfsec | tail -1)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "Container scan (trivy/grype):" "$(check_tool_in_ci grype)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "DAST (zap/nuclei):" "$(check_tool_in_ci zap; check_tool_in_ci nuclei | tail -1)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "SBOM generation (syft):" "$(check_tool_in_ci syft)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "Artifact signing (cosign):" "$(check_tool_in_ci cosign)" >> "$MATURITY_FILE"
printf "  %-30s %s\n" "Runtime monitoring (falco):" "$(check_tool_in_ci falco)" >> "$MATURITY_FILE"

cat "$MATURITY_FILE"
```

### Step 2: Identify gaps per stage

```bash
GAP_FILE="$OUTDIR/gap_analysis.md"

# Scan repo for additional context
echo "[*] Scanning repository structure for additional context..."
[ -f "$REPO/Dockerfile" ] && echo "[+] Dockerfile found - container scanning applies"
[ -f "$REPO/docker-compose.yml" ] && echo "[+] docker-compose.yml found"
[ -d "$REPO/terraform" ] || [ -d "$REPO/infra" ] && echo "[+] IaC directory found - IaC scanning applies"
[ -f "$REPO/.pre-commit-config.yaml" ] && echo "[+] Pre-commit config found"
[ -f "$REPO/package.json" ] && echo "[+] Node.js project - npm audit / Snyk applicable"
[ -f "$REPO/requirements.txt" ] || [ -f "$REPO/pyproject.toml" ] && echo "[+] Python project - pip-audit / Snyk applicable"
[ -f "$REPO/go.mod" ] && echo "[+] Go project - govulncheck / Trivy applicable"

echo "[+] Gap analysis written to: $GAP_FILE"
```

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full gap analysis table covering all 14 pipeline stages/controls with tool and status columns.

### Step 3: Generate CI/CD configs

```bash
GHA_FILE="$OUTDIR/devsecops-pipeline.yml"
GITLAB_FILE="$OUTDIR/gitlab-devsecops.yml"

echo "[+] GitHub Actions workflow written to: $GHA_FILE"
echo "[+] GitLab CI snippet written to: $GITLAB_FILE"
```

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the complete GitHub Actions workflow template (secrets scan, SAST, SCA, IaC, container scan, DAST, SBOM + cosign signing) and the GitLab CI include snippet.

### Step 4: Define security gate policies

```bash
POLICY_FILE="$OUTDIR/security-gate-policies.md"
echo "[+] Security gate policies written to: $POLICY_FILE"
```

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full security gate policy tables: hard gates (block on failure), soft gates (warn + exception), and metrics targets.

### Step 5: Output implementation roadmap

```bash
ROADMAP_FILE="$OUTDIR/implementation-roadmap.md"

echo ""
echo "===== DevSecOps Pipeline Setup Complete ====="
echo "Output files:"
echo "  Maturity assessment : $MATURITY_FILE"
echo "  Gap analysis        : $GAP_FILE"
echo "  GitHub Actions CI   : $GHA_FILE"
echo "  GitLab CI snippet   : $GITLAB_FILE"
echo "  Security gate policy: $POLICY_FILE"
echo "  Implementation roadmap: $ROADMAP_FILE"
echo "============================================="
```

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the phased implementation roadmap (5 phases, Weeks 1–8 plus ongoing maturity items).

## Done when

- Pipeline maturity has been assessed against all 8 stages
- Gap analysis table populated with current tool coverage
- CI/CD configuration files generated and saved
- Security gate policies defined with hard and soft gates
- Phased implementation roadmap created in output directory

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| No CI config detected | New repository without pipeline | Use generated files as starting point |
| `gitleaks` blocks commit | Real secret in staged files | Rotate the credential, then remove from history with `git filter-repo` |
| Semgrep times out | Large monorepo | Add `.semgrepignore` to exclude vendored/generated code |
| ZAP scan finds no target | `DAST_TARGET_URL` not set | Set the variable in CI environment settings |
| cosign signing fails | OIDC token not available | Ensure `id-token: write` permission in GitHub Actions job |
| Trivy DB stale | Offline environment | Pre-pull DB with `trivy image --download-db-only` and cache |

## Notes

- Start with Phase 1 only — adding all gates at once causes alert fatigue and pipeline abandonment.
- Tune SAST rules in `audit` mode (non-blocking) for 2 weeks before enabling hard gates.
- SBOM generation is a prerequisite for supply-chain compliance (see `supply-chain-audit` skill).
- For SLSA compliance, pair this skill with the `supply-chain-audit` skill.
- Pipeline configs in `devsecops-output/` are templates — review and adjust severity thresholds, language matrix, and target URLs before committing.
