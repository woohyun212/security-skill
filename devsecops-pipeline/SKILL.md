---
name: devsecops-pipeline
description: CI/CD security pipeline setup with SAST, SCA, DAST, container scanning, and SBOM
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
cat > "$GAP_FILE" << 'EOF'
# DevSecOps Pipeline Gap Analysis

| Stage | Control | Tools | Status |
|-------|---------|-------|--------|
| Plan | Threat modeling | STRIDE / threat-dragon | Manual review required |
| Code | Pre-commit secrets scan | gitleaks, hadolint | Check step 1 output |
| Build | SAST | Semgrep, CodeQL, SonarQube | Check step 1 output |
| Build | SCA | Snyk, Dependabot, Trivy | Check step 1 output |
| Build | IaC scan | Checkov, tfsec | Check step 1 output |
| Build | Container scan | Trivy, Grype | Check step 1 output |
| Test | DAST | OWASP ZAP, Nuclei | Check step 1 output |
| Test | API security | OWASP ZAP API scan | Check step 1 output |
| Release | SBOM generation | Syft (CycloneDX/SPDX) | Check step 1 output |
| Release | Artifact signing | cosign + Sigstore/Rekor | Check step 1 output |
| Deploy | Admission control | OPA Gatekeeper, Kyverno | K8s environments only |
| Deploy | Network policies | Calico, Cilium | K8s environments only |
| Operate | Runtime monitoring | Falco, CSPM | Check step 1 output |
| Monitor | SIEM integration | Splunk, Elastic SIEM | Environment-specific |
EOF

echo "[+] Gap analysis written to: $GAP_FILE"

# Scan repo for additional context
echo ""
echo "[*] Scanning repository structure for additional context..."
[ -f "$REPO/Dockerfile" ] && echo "[+] Dockerfile found - container scanning applies"
[ -f "$REPO/docker-compose.yml" ] && echo "[+] docker-compose.yml found"
[ -d "$REPO/terraform" ] || [ -d "$REPO/infra" ] && echo "[+] IaC directory found - IaC scanning applies"
[ -f "$REPO/.pre-commit-config.yaml" ] && echo "[+] Pre-commit config found"
[ -f "$REPO/package.json" ] && echo "[+] Node.js project - npm audit / Snyk applicable"
[ -f "$REPO/requirements.txt" ] || [ -f "$REPO/pyproject.toml" ] && echo "[+] Python project - pip-audit / Snyk applicable"
[ -f "$REPO/go.mod" ] && echo "[+] Go project - govulncheck / Trivy applicable"
```

### Step 3: Generate CI/CD configs

```bash
# GitHub Actions: full DevSecOps pipeline workflow
GHA_FILE="$OUTDIR/devsecops-pipeline.yml"

cat > "$GHA_FILE" << 'YAML'
name: DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  id-token: write   # required for cosign keyless signing

jobs:
  # ── Stage: Code ──────────────────────────────────────────
  secrets-scan:
    name: Secrets Scan (gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  lint-dockerfile:
    name: Dockerfile Lint (hadolint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: warning

  # ── Stage: Build / SAST ──────────────────────────────────
  sast-semgrep:
    name: SAST (Semgrep)
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/ci
            p/owasp-top-ten
            p/security-audit
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

  sast-codeql:
    name: SAST (CodeQL)
    runs-on: ubuntu-latest
    needs: secrets-scan
    strategy:
      matrix:
        language: [javascript, python]  # adjust to your stack
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: /language:${{ matrix.language }}

  # ── Stage: Build / SCA ───────────────────────────────────
  sca-trivy:
    name: SCA (Trivy filesystem)
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: HIGH,CRITICAL
          exit-code: 1
          format: sarif
          output: trivy-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

  # ── Stage: Build / IaC ───────────────────────────────────
  iac-checkov:
    name: IaC Scan (Checkov)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform,dockerfile,kubernetes
          soft_fail: false
          output_format: sarif
          output_file_path: checkov-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov-results.sarif

  # ── Stage: Build / Container ─────────────────────────────
  container-scan:
    name: Container Scan (Trivy image)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t app:${{ github.sha }} .
      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          severity: HIGH,CRITICAL
          exit-code: 1
          format: sarif
          output: container-scan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: container-scan.sarif

  # ── Stage: Test / DAST ───────────────────────────────────
  dast-zap:
    name: DAST (OWASP ZAP baseline)
    runs-on: ubuntu-latest
    needs: [sast-semgrep, sca-trivy]
    steps:
      - uses: actions/checkout@v4
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: ${{ vars.DAST_TARGET_URL }}
          rules_file_name: .zap/rules.tsv
          fail_action: true

  # ── Stage: Release / SBOM + Signing ──────────────────────
  sbom-and-sign:
    name: SBOM Generation + Signing (syft + cosign)
    runs-on: ubuntu-latest
    needs: [container-scan]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Install syft
        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
      - name: Generate SBOM (CycloneDX)
        run: syft . -o cyclonedx-json > sbom.cyclonedx.json
      - name: Generate SBOM (SPDX)
        run: syft . -o spdx-json > sbom.spdx.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.*.json
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign image (keyless via OIDC)
        run: |
          cosign sign --yes \
            ${{ vars.REGISTRY }}/${{ vars.IMAGE_NAME }}:${{ github.sha }}
YAML

echo "[+] GitHub Actions workflow written to: $GHA_FILE"

# GitLab CI include snippet
GITLAB_FILE="$OUTDIR/gitlab-devsecops.yml"
cat > "$GITLAB_FILE" << 'YAML'
# GitLab CI - DevSecOps security stages include
# Add to your .gitlab-ci.yml: include: - local: gitlab-devsecops.yml

stages:
  - secrets
  - sast
  - sca
  - dast
  - release

gitleaks:
  stage: secrets
  image: zricethezav/gitleaks:latest
  script:
    - gitleaks detect --source . --exit-code 1

semgrep:
  stage: sast
  image: returntocorp/semgrep
  script:
    - semgrep ci --config=auto --error
  variables:
    SEMGREP_APP_TOKEN: $SEMGREP_APP_TOKEN

trivy-fs:
  stage: sca
  image: aquasec/trivy:latest
  script:
    - trivy fs --exit-code 1 --severity HIGH,CRITICAL .

checkov:
  stage: sast
  image: bridgecrew/checkov:latest
  script:
    - checkov -d . --framework terraform,dockerfile,kubernetes

zap-baseline:
  stage: dast
  image: ghcr.io/zaproxy/zaproxy:stable
  script:
    - zap-baseline.py -t $DAST_TARGET_URL -r zap-report.html
  artifacts:
    paths: [zap-report.html]
    when: always

syft-sbom:
  stage: release
  image: anchore/syft:latest
  script:
    - syft . -o cyclonedx-json > sbom.cyclonedx.json
  artifacts:
    paths: [sbom.cyclonedx.json]
  only:
    - main
YAML

echo "[+] GitLab CI snippet written to: $GITLAB_FILE"
```

### Step 4: Define security gate policies

```bash
POLICY_FILE="$OUTDIR/security-gate-policies.md"
cat > "$POLICY_FILE" << 'EOF'
# Security Gate Policies

## Hard Gates (block merge/deploy on failure)

| Gate | Condition | Tool | Stage |
|------|-----------|------|-------|
| Secrets detected | Any secret found in diff | gitleaks | Code |
| Critical SAST finding | CVSS >= 9.0 in new code | Semgrep / CodeQL | Build |
| Critical dependency CVE | CVSS >= 9.0 in direct deps | Trivy / Snyk | Build |
| Critical container CVE | CVSS >= 9.0 in base image | Trivy / Grype | Build |
| IaC critical misconfiguration | Checkov CRITICAL policy fail | Checkov / tfsec | Build |
| DAST high finding | High-severity active finding | OWASP ZAP | Test |
| SBOM missing | No SBOM artifact on release | Syft | Release |
| Unsigned artifact | Image not signed | cosign | Release |

## Soft Gates (warn; require documented exception)

| Gate | Condition | Tool |
|------|-----------|------|
| High SAST finding | CVSS 7.0–8.9 in new code | Semgrep |
| High dependency CVE | CVSS 7.0–8.9 in transitive deps | Trivy |
| Dockerfile best-practice violation | hadolint DL* rules | hadolint |
| License compliance | Copyleft license in dependency | Trivy / FOSSA |

## Metrics Targets

| Metric | Target |
|--------|--------|
| Vulnerabilities introduced per sprint | < 2 high, 0 critical |
| Mean Time to Detect (MTTD) | < 24 hours |
| Mean Time to Remediate (MTTR) critical | < 48 hours |
| False positive rate (SAST) | < 15% |
| Pipeline security coverage | 100% of repos |
| SBOM freshness | Generated on every release |
EOF

echo "[+] Security gate policies written to: $POLICY_FILE"
```

### Step 5: Output implementation roadmap

```bash
ROADMAP_FILE="$OUTDIR/implementation-roadmap.md"
cat > "$ROADMAP_FILE" << 'EOF'
# DevSecOps Implementation Roadmap

## Phase 1 — Foundation (Week 1–2)
- [ ] Enable gitleaks pre-commit hook (`gitleaks protect --staged`)
- [ ] Add SAST job (Semgrep `p/ci` ruleset) to existing CI pipeline
- [ ] Enable Dependabot / renovate for dependency updates
- [ ] Integrate Trivy filesystem scan with HIGH/CRITICAL gate

## Phase 2 — Build hardening (Week 3–4)
- [ ] Add CodeQL for primary application language
- [ ] Add Checkov IaC scan if Terraform/Kubernetes present
- [ ] Add container image scan (Trivy or Grype) to build stage
- [ ] Configure SonarQube/SonarCloud for code quality + security

## Phase 3 — Test & Release (Week 5–6)
- [ ] Deploy OWASP ZAP baseline scan against staging environment
- [ ] Generate SBOM (CycloneDX) on every release branch merge
- [ ] Implement cosign keyless signing for release images
- [ ] Add Nuclei scan for known CVE/misconfiguration templates

## Phase 4 — Operate & Monitor (Week 7–8)
- [ ] Deploy Falco to Kubernetes clusters with default ruleset
- [ ] Enable CSPM (AWS Security Hub / GCP SCC / Azure Defender)
- [ ] Connect pipeline findings to SIEM (Splunk / Elastic)
- [ ] Establish vulnerability dashboard and MTTR tracking

## Phase 5 — Mature (Ongoing)
- [ ] Tune SAST rulesets to reduce false positives below 15%
- [ ] Implement IAST agent for integration test environments
- [ ] Enforce policy-as-code via OPA Gatekeeper (Kubernetes)
- [ ] Quarterly threat modeling sessions per STRIDE methodology
- [ ] Achieve SLSA Level 2+ for critical services
EOF

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
