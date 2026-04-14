---
name: supply-chain-audit
description: Supply chain security audit with SCA scanning (trivy/grype), SLSA compliance assessment, and SBOM generation (CycloneDX/SPDX)
license: MIT
metadata:
  category: vuln-analysis
  locale: en
  phase: v1
---

## What this skill does

Performs a comprehensive software supply chain security assessment: inventories all dependencies, runs SCA tooling across detected ecosystems, evaluates SLSA framework compliance (Levels 1–4), generates a CycloneDX/SPDX SBOM, and analyzes exposure across four attack vector categories (dependency, build pipeline, source code, distribution). Outputs a risk findings table, SLSA compliance matrix, and prioritized remediation roadmap.

## When to use

- When evaluating supply chain risk before a major release or acquisition
- When responding to a supply chain incident (SolarWinds/XZ-style events)
- When achieving SLSA Level 2+ compliance for a service
- When preparing a software bill of materials for a customer or regulator
- When auditing third-party code integrated into your codebase

## Prerequisites

```bash
# Core SCA and SBOM tools
brew install trivy grype syft cosign gitleaks   # macOS
# Linux:
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Per-ecosystem tools (install what applies)
npm install -g snyk          # Node.js SCA + license check
pip install pip-audit        # Python SCA
go install golang.org/x/vuln/cmd/govulncheck@latest  # Go

# Secrets scanning
brew install trufflesecurity/trufflehog/trufflehog
```

- `SECSKILL_REPO_PATH`: local repository root
- `SECSKILL_IMAGE_NAME` (optional): container image name:tag to include in scan
- `SNYK_TOKEN` (optional): enables Snyk authenticated scans

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_REPO_PATH` | Required | Repository root path |
| `SECSKILL_OUTPUT_DIR` | Optional | Output directory (default: `./supply-chain-output`) |
| `SECSKILL_IMAGE_NAME` | Optional | Container image to include in SBOM and vulnerability scan |
| `SNYK_TOKEN` | Optional | Snyk API token for authenticated SCA |
| `SECSKILL_SBOM_FORMAT` | Optional | `cyclonedx` or `spdx` (default: both) |

## Workflow

### Step 1: Inventory dependencies and detect ecosystem

```bash
export REPO="${SECSKILL_REPO_PATH:?Set SECSKILL_REPO_PATH}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./supply-chain-output}"
mkdir -p "$OUTDIR"

SUMMARY="$OUTDIR/audit_summary.txt"
echo "Supply Chain Audit Report" > "$SUMMARY"
echo "Repo   : $REPO" >> "$SUMMARY"
echo "Date   : $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$SUMMARY"
echo "" >> "$SUMMARY"

echo "[*] Inventorying ecosystems in: $REPO"

HAS_NODE=false; HAS_PYTHON=false; HAS_GO=false; HAS_JAVA=false; HAS_RUBY=false; HAS_DOCKER=false

[ -f "$REPO/package.json" ]       && HAS_NODE=true   && echo "[+] Node.js (package.json)"
[ -f "$REPO/requirements.txt" ] \
  || [ -f "$REPO/Pipfile" ] \
  || [ -f "$REPO/pyproject.toml" ] && HAS_PYTHON=true && echo "[+] Python"
[ -f "$REPO/go.mod" ]             && HAS_GO=true     && echo "[+] Go (go.mod)"
[ -f "$REPO/pom.xml" ] \
  || [ -f "$REPO/build.gradle" ]   && HAS_JAVA=true   && echo "[+] Java (Maven/Gradle)"
[ -f "$REPO/Gemfile" ]            && HAS_RUBY=true   && echo "[+] Ruby (Gemfile)"
[ -f "$REPO/Dockerfile" ]         && HAS_DOCKER=true && echo "[+] Docker image"

# Count direct dependencies per ecosystem
echo "" >> "$SUMMARY"
echo "Ecosystems detected:" >> "$SUMMARY"
[ "$HAS_NODE" = "true" ]   && printf "  %-12s %s direct deps\n" "Node.js:" "$(jq '.dependencies | length' "$REPO/package.json" 2>/dev/null || echo '?')" >> "$SUMMARY"
[ "$HAS_PYTHON" = "true" ] && printf "  %-12s %s packages\n" "Python:" "$(wc -l < "$REPO/requirements.txt" 2>/dev/null || echo '?')" >> "$SUMMARY"
[ "$HAS_GO" = "true" ]     && printf "  %-12s %s modules\n" "Go:" "$(grep -c '^require' "$REPO/go.mod" 2>/dev/null || echo '?')" >> "$SUMMARY"

# Check for lockfiles (critical for supply chain integrity)
echo "" >> "$SUMMARY"
echo "Lockfile status (integrity anchors):" >> "$SUMMARY"
[ -f "$REPO/package-lock.json" ] && echo "  [PRESENT] package-lock.json" >> "$SUMMARY" \
  || ([ "$HAS_NODE" = "true" ] && echo "  [MISSING] package-lock.json - HIGH RISK" >> "$SUMMARY")
[ -f "$REPO/yarn.lock" ]         && echo "  [PRESENT] yarn.lock" >> "$SUMMARY"
[ -f "$REPO/Pipfile.lock" ]      && echo "  [PRESENT] Pipfile.lock" >> "$SUMMARY" \
  || ([ "$HAS_PYTHON" = "true" ] && echo "  [MISSING] Pipfile.lock - consider pip-compile" >> "$SUMMARY")
[ -f "$REPO/go.sum" ]            && echo "  [PRESENT] go.sum" >> "$SUMMARY" \
  || ([ "$HAS_GO" = "true" ]    && echo "  [MISSING] go.sum - HIGH RISK" >> "$SUMMARY")

cat "$SUMMARY"
```

### Step 2: Run SCA tools per ecosystem

```bash
echo ""
echo "[*] Running SCA scans..."

# ── Node.js ──────────────────────────────────────────────
if [ "$HAS_NODE" = "true" ]; then
  cd "$REPO"
  if [ ! -f "package-lock.json" ]; then
    echo "[*] Generating lockfile for audit..."
    npm install --package-lock-only --silent 2>/dev/null
  fi
  npm audit --json > "$OUTDIR/npm_audit.json" 2>/dev/null
  NPM_CRIT=$(jq '.metadata.vulnerabilities.critical // 0' "$OUTDIR/npm_audit.json" 2>/dev/null)
  NPM_HIGH=$(jq '.metadata.vulnerabilities.high // 0' "$OUTDIR/npm_audit.json" 2>/dev/null)
  echo "[+] npm audit: critical=$NPM_CRIT high=$NPM_HIGH"

  if command -v snyk >/dev/null 2>&1 && [ -n "$SNYK_TOKEN" ]; then
    snyk test --json > "$OUTDIR/snyk_node.json" 2>/dev/null
    echo "[+] Snyk Node.js scan complete"
  fi
  cd - > /dev/null
fi

# ── Python ───────────────────────────────────────────────
if [ "$HAS_PYTHON" = "true" ]; then
  if command -v pip-audit >/dev/null 2>&1; then
    PIPARGS=""
    [ -f "$REPO/requirements.txt" ] && PIPARGS="-r $REPO/requirements.txt"
    pip-audit $PIPARGS --format=json --output="$OUTDIR/pip_audit.json" 2>/dev/null
    PIP_VULNS=$(jq '[.[].vulns[]] | length' "$OUTDIR/pip_audit.json" 2>/dev/null || echo 0)
    echo "[+] pip-audit: $PIP_VULNS findings"
  fi
fi

# ── Go ───────────────────────────────────────────────────
if [ "$HAS_GO" = "true" ]; then
  if command -v govulncheck >/dev/null 2>&1; then
    cd "$REPO"
    govulncheck -json ./... > "$OUTDIR/govulncheck.json" 2>/dev/null
    GO_VULNS=$(jq '[.[] | select(.finding)] | length' "$OUTDIR/govulncheck.json" 2>/dev/null || echo 0)
    echo "[+] govulncheck: $GO_VULNS findings"
    cd - > /dev/null
  fi
fi

# ── Trivy (filesystem — all ecosystems) ──────────────────
if command -v trivy >/dev/null 2>&1; then
  trivy fs \
    --severity HIGH,CRITICAL \
    --format json \
    --output "$OUTDIR/trivy_fs.json" \
    --quiet \
    "$REPO" 2>/dev/null
  TRIVY_TOTAL=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$OUTDIR/trivy_fs.json" 2>/dev/null || echo 0)
  TRIVY_CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$OUTDIR/trivy_fs.json" 2>/dev/null || echo 0)
  echo "[+] Trivy fs: total=$TRIVY_TOTAL critical=$TRIVY_CRIT"
fi

# ── Container image ──────────────────────────────────────
if [ -n "$SECSKILL_IMAGE_NAME" ] && command -v grype >/dev/null 2>&1; then
  grype "$SECSKILL_IMAGE_NAME" -o json > "$OUTDIR/grype_image.json" 2>/dev/null
  GRYPE_CRIT=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$OUTDIR/grype_image.json" 2>/dev/null || echo 0)
  GRYPE_HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' "$OUTDIR/grype_image.json" 2>/dev/null || echo 0)
  echo "[+] Grype image: critical=$GRYPE_CRIT high=$GRYPE_HIGH"
fi

# ── Secrets in history ───────────────────────────────────
if command -v trufflehog >/dev/null 2>&1; then
  trufflehog git "file://$REPO" --json --no-update > "$OUTDIR/trufflehog.json" 2>/dev/null
  SECRET_COUNT=$(wc -l < "$OUTDIR/trufflehog.json" 2>/dev/null || echo 0)
  echo "[+] TruffleHog: $SECRET_COUNT potential secrets in git history"
elif command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$REPO" --report-path "$OUTDIR/gitleaks.json" --report-format json 2>/dev/null
  echo "[+] gitleaks: scan complete (see $OUTDIR/gitleaks.json)"
fi

echo "[+] SCA scans complete"
```

### Step 3: Assess SLSA compliance

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full SLSA compliance matrix, level-by-level checklist, and quick-win guidance.

```bash
SLSA_FILE="$OUTDIR/slsa_compliance.md"

echo "[+] SLSA compliance matrix written to: $SLSA_FILE"

# Auto-check a few SLSA indicators
echo ""
echo "[*] Auto-detecting SLSA indicators..."

if [ -d "$REPO/.github/workflows" ]; then
  # Check for pinned actions (SHA pinning)
  PINNED=$(grep -rh 'uses:' "$REPO/.github/workflows/" 2>/dev/null | grep -c '@[0-9a-f]\{40\}' || echo 0)
  TOTAL_USES=$(grep -rh 'uses:' "$REPO/.github/workflows/" 2>/dev/null | wc -l || echo 0)
  echo "  GitHub Actions SHA-pinned: $PINNED / $TOTAL_USES steps"
  [ "$PINNED" -eq "$TOTAL_USES" ] && echo "  [PASS] All actions pinned" || echo "  [WARN] Some actions use tags/branches instead of SHA"

  # Check for provenance generation
  grep -rl 'attest-build-provenance\|sigstore\|cosign' "$REPO/.github/workflows/" >/dev/null 2>&1 \
    && echo "  [PASS] Provenance / signing detected in workflows" \
    || echo "  [MISS] No provenance generation found"
fi

# Check branch protection via git config (local only)
[ -f "$REPO/.github/branch-protection.json" ] \
  || grep -q 'required_status_checks' "$REPO/.github/settings.yml" 2>/dev/null \
  && echo "  [PASS] Branch protection config found" \
  || echo "  [UNKNOWN] Branch protection status requires GitHub API access"
```

### Step 4: Generate SBOM

```bash
echo ""
echo "[*] Generating SBOM..."
FORMAT="${SECSKILL_SBOM_FORMAT:-both}"

if command -v syft >/dev/null 2>&1; then
  if [ "$FORMAT" = "cyclonedx" ] || [ "$FORMAT" = "both" ]; then
    syft "$REPO" -o cyclonedx-json > "$OUTDIR/sbom.cyclonedx.json" 2>/dev/null
    COMP_COUNT=$(jq '.components | length' "$OUTDIR/sbom.cyclonedx.json" 2>/dev/null || echo 0)
    echo "[+] CycloneDX SBOM: $COMP_COUNT components -> $OUTDIR/sbom.cyclonedx.json"
  fi

  if [ "$FORMAT" = "spdx" ] || [ "$FORMAT" = "both" ]; then
    syft "$REPO" -o spdx-json > "$OUTDIR/sbom.spdx.json" 2>/dev/null
    PKG_COUNT=$(jq '.packages | length' "$OUTDIR/sbom.spdx.json" 2>/dev/null || echo 0)
    echo "[+] SPDX SBOM: $PKG_COUNT packages -> $OUTDIR/sbom.spdx.json"
  fi

  # Include container image if provided
  if [ -n "$SECSKILL_IMAGE_NAME" ]; then
    syft "$SECSKILL_IMAGE_NAME" -o cyclonedx-json > "$OUTDIR/sbom-image.cyclonedx.json" 2>/dev/null
    IMG_COMP=$(jq '.components | length' "$OUTDIR/sbom-image.cyclonedx.json" 2>/dev/null || echo 0)
    echo "[+] Image SBOM: $IMG_COMP components -> $OUTDIR/sbom-image.cyclonedx.json"
  fi
else
  echo "[-] syft not found. Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"
fi
```

### Step 5: Analyze attack surface per vector category

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full attack surface analysis tables and checklists covering dependency, build pipeline, source code, and distribution attack vectors.

```bash
ATTACK_FILE="$OUTDIR/attack_surface_analysis.md"
echo "[+] Attack surface analysis written to: $ATTACK_FILE"
```

### Step 6: Output findings with remediation

```bash
FINDINGS_FILE="$OUTDIR/findings_and_remediation.md"
cat > "$FINDINGS_FILE" << 'HEADER'
# Supply Chain Audit Findings

## Risk Findings Summary

| Severity | Area | Finding | Remediation |
|----------|------|---------|-------------|
HEADER

# Populate findings from scan outputs
{
  # Missing lockfiles
  [ "$HAS_NODE" = "true" ] && [ ! -f "$REPO/package-lock.json" ] && [ ! -f "$REPO/yarn.lock" ] && \
    echo "| HIGH | Dependency | Missing Node.js lockfile | Run \`npm install\` and commit package-lock.json |"
  [ "$HAS_PYTHON" = "true" ] && [ ! -f "$REPO/Pipfile.lock" ] && \
    echo "| MEDIUM | Dependency | Missing Python lockfile | Use \`pip-compile\` or \`poetry lock\` |"
  [ "$HAS_GO" = "true" ] && [ ! -f "$REPO/go.sum" ] && \
    echo "| HIGH | Dependency | Missing go.sum | Run \`go mod tidy\` and commit go.sum |"

  # Trivy critical findings
  if [ -f "$OUTDIR/trivy_fs.json" ]; then
    jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL") |
      "| CRITICAL | Dependency | \(.VulnerabilityID) in \(.PkgName) \(.InstalledVersion) | Upgrade to \(.FixedVersion // "check upstream") |"' \
      "$OUTDIR/trivy_fs.json" 2>/dev/null | head -10
  fi

  # Secrets in history
  [ -f "$OUTDIR/gitleaks.json" ] && [ -s "$OUTDIR/gitleaks.json" ] && \
    echo "| CRITICAL | Source Code | Secrets detected in repository | Rotate credentials immediately; purge with git-filter-repo |"

  # Unsigned artifacts
  [ -z "$(command -v cosign 2>/dev/null)" ] && \
    echo "| MEDIUM | Distribution | No artifact signing configured | Install cosign and sign release images |"

} >> "$FINDINGS_FILE"

echo "" >> "$FINDINGS_FILE"
echo "" >> "$FINDINGS_FILE"

# Remediation roadmap template is in REFERENCE.md
echo "" >> "$FINDINGS_FILE"
echo "> See REFERENCE.md for the full remediation roadmap template (Immediate / Short-term / Medium-term / Long-term)." >> "$FINDINGS_FILE"

echo ""
echo "===== Supply Chain Audit Complete ====="
echo "Output directory: $OUTDIR"
echo ""
echo "Files generated:"
echo "  Audit summary        : $SUMMARY"
echo "  SLSA compliance      : $SLSA_FILE"
echo "  SBOM (CycloneDX)     : $OUTDIR/sbom.cyclonedx.json"
echo "  SBOM (SPDX)          : $OUTDIR/sbom.spdx.json"
echo "  Attack surface       : $ATTACK_FILE"
echo "  Findings + roadmap   : $FINDINGS_FILE"
[ -f "$OUTDIR/trivy_fs.json" ]   && echo "  Trivy fs scan        : $OUTDIR/trivy_fs.json"
[ -f "$OUTDIR/npm_audit.json" ]  && echo "  npm audit            : $OUTDIR/npm_audit.json"
[ -f "$OUTDIR/pip_audit.json" ]  && echo "  pip-audit            : $OUTDIR/pip_audit.json"
[ -f "$OUTDIR/govulncheck.json" ] && echo "  govulncheck          : $OUTDIR/govulncheck.json"
[ -f "$OUTDIR/grype_image.json" ] && echo "  Grype image scan     : $OUTDIR/grype_image.json"
echo "======================================="
```

## Done when

- All detected ecosystems have been scanned with SCA tooling
- SLSA compliance matrix populated with auto-detected and manual checklist items
- CycloneDX and/or SPDX SBOM generated in output directory
- Attack surface analyzed across all four vector categories
- Risk findings table and remediation roadmap written to output directory

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| syft produces empty SBOM | No package manifest found | Ensure lockfiles exist; specify `--scope all-layers` for container images |
| Trivy DB download fails | Network/proxy issue | Run `trivy image --download-db-only` separately with correct proxy settings |
| govulncheck panics | Module graph inconsistency | Run `go mod tidy` in the repository first |
| npm audit 404 error | Registry unreachable or private packages | Set `NPM_CONFIG_REGISTRY` env var; use `--registry` flag |
| grype cannot pull image | Registry auth required | Run `docker login` or set `DOCKER_CONFIG` before running grype |
| TruffleHog no output | Shallow clone | Re-clone with `git clone --no-single-branch --unshallow` |

## Notes

- **Lockfiles are the single most impactful supply chain control** — ensure they are always committed and CI fails if they are out of sync.
- Pair with the `devsecops-pipeline` skill to automate these checks in CI on every pull request.
- The SBOM generated here is a point-in-time snapshot; regenerate on every release.
- SLSA Level 2 is the practical target for most teams; Level 3 requires significant CI platform investment.
- Socket.dev (`socket.dev`) provides real-time npm/PyPI behavioral analysis beyond CVE databases; for regulated industries (FedRAMP, PCI-DSS), the generated SBOM satisfies common evidence requirements for component inventory.
