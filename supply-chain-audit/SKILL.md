---
name: supply-chain-audit
description: Software supply chain security assessment with SLSA compliance and SBOM generation
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

```bash
SLSA_FILE="$OUTDIR/slsa_compliance.md"
cat > "$SLSA_FILE" << 'EOF'
# SLSA Compliance Matrix

## Level Definitions

| Level | Requirements Summary |
|-------|---------------------|
| SLSA 1 | Build scripted; provenance generated |
| SLSA 2 | Build service used; provenance signed by builder |
| SLSA 3 | Hardened build platform; auditable build process |
| SLSA 4 | Hermetic, reproducible builds; two-party review |

## Current Assessment Checklist

### SLSA Level 1
- [ ] Build process is fully scripted (no manual steps)
- [ ] Build provenance document generated (who built what, from where)
- [ ] Provenance available to consumers

### SLSA Level 2
- [ ] Builds run on a hosted CI/CD platform (GitHub Actions, GitLab CI, etc.)
- [ ] Build provenance is signed by the build platform
- [ ] Source is version-controlled with branch protection on main
- [ ] Two-party code review required for changes to main

### SLSA Level 3
- [ ] Build platform prevents parameter injection from source
- [ ] Build instructions cannot be influenced by untrusted input
- [ ] All transitive build dependencies are pinned by hash
- [ ] Build environment is ephemeral (no persistent state)
- [ ] Provenance is non-falsifiable (signed by hardware/HSM)

### SLSA Level 4
- [ ] Build is hermetic (no network access during build)
- [ ] Build is reproducible bit-for-bit
- [ ] Source history is retained indefinitely
- [ ] All changes reviewed by two trusted persons

## Quick Wins (toward SLSA Level 2)

1. Pin all GitHub Actions to commit SHAs (not tags):
   `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`
2. Enable branch protection rules (require PR + review on main)
3. Add `actions/attest-build-provenance` step to release workflow
4. Use `cosign sign` with OIDC keyless signing for released artifacts
EOF

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

```bash
ATTACK_FILE="$OUTDIR/attack_surface_analysis.md"
cat > "$ATTACK_FILE" << 'EOF'
# Supply Chain Attack Surface Analysis

## Attack Vector Categories

### 1. Dependency Attacks

| Vector | Risk | Detection | Mitigation |
|--------|------|-----------|------------|
| Typosquatting | HIGH | Socket.dev, manual review | Namespace reservation, private registry |
| Dependency confusion | HIGH | Trivy, Snyk | Scoped packages, private registry with priority |
| Malicious updates | HIGH | Snyk, Dependabot, Socket.dev | Pin versions + hash; staged rollout |
| Protestware | MEDIUM | Manual audit, Socket.dev | Review changelogs; pin exact versions |
| Malicious install scripts | HIGH | Socket.dev | `npm install --ignore-scripts`; audit `postinstall` hooks |

**Assessment checklist:**
- [ ] All direct dependencies pinned to exact versions (not ranges)
- [ ] Lockfiles committed and integrity-checked in CI
- [ ] Private registry configured to prevent dependency confusion
- [ ] Package namespaces reserved in all used registries
- [ ] `postinstall` / lifecycle scripts audited for each new dependency
- [ ] Socket.dev or similar behavior-analysis tool integrated

### 2. Build Pipeline Attacks

| Vector | Risk | Detection | Mitigation |
|--------|------|-----------|------------|
| CI/CD poisoning | CRITICAL | Workflow review, SLSA | Least-privilege secrets; ephemeral runners |
| Artifact tampering | HIGH | cosign, in-toto | Sign artifacts; verify before deploy |
| Cache poisoning | HIGH | Cache key audit | Hash-based cache keys; isolated caches |
| Workflow injection | CRITICAL | Static analysis, manual review | Avoid `${{ github.event.* }}` in `run:` steps |

**Assessment checklist:**
- [ ] CI secrets are minimum-scope and rotated regularly
- [ ] Build runners are ephemeral (no persistent state)
- [ ] All release artifacts are signed (cosign / GPG)
- [ ] No untrusted input flows into `run:` shell steps
- [ ] Third-party GitHub Actions pinned to commit SHA

### 3. Source Code Attacks

| Vector | Risk | Detection | Mitigation |
|--------|------|-----------|------------|
| Compromised maintainer account | CRITICAL | Anomaly detection, audit logs | MFA enforcement; branch protection |
| Trojan source (Unicode attacks) | MEDIUM | Semgrep, CodeQL | Unicode normalization linting |
| Repository takeover (abandoned) | HIGH | Periodic audit | Monitor all dependencies for ownership changes |
| Malicious PR/commit | HIGH | Code review, gitleaks | Required reviews; signed commits |

**Assessment checklist:**
- [ ] MFA enforced for all contributors with write access
- [ ] Branch protection: require PR + 2 reviewers on main
- [ ] Signed commits enforced (`git config commit.gpgsign true`)
- [ ] Trojan-source / bidirectional Unicode detection in SAST
- [ ] Dependency ownership changes monitored (Socket.dev / deps.dev)

### 4. Distribution Attacks

| Vector | Risk | Detection | Mitigation |
|--------|------|-----------|------------|
| CDN poisoning | HIGH | SRI hashes | Subresource Integrity (SRI) on all CDN assets |
| Update hijacking | HIGH | cosign, TUF | Use TUF-compliant update framework; verify signatures |
| Registry compromise | CRITICAL | Signature verification | Verify cosign signatures before deploy |
| Package metadata tampering | MEDIUM | Hash verification | Pin by digest; verify checksums |

**Assessment checklist:**
- [ ] SRI hashes applied to all external CDN resources
- [ ] Container images verified by digest before deployment
- [ ] cosign signature verification in deployment pipeline
- [ ] Artifact checksums published and verified
EOF

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

cat >> "$FINDINGS_FILE" << 'EOF'
## Remediation Roadmap

### Immediate (< 48h)
1. Rotate any secrets found by gitleaks/TruffleHog — treat all exposed secrets as compromised
2. Patch all CRITICAL CVEs in direct dependencies
3. Commit missing lockfiles (package-lock.json, go.sum, Pipfile.lock)

### Short-term (1–2 weeks)
4. Pin all GitHub Actions to commit SHAs
5. Enable branch protection: require PRs + 2 reviewers on main
6. Add Trivy/Grype scan to CI pipeline as a blocking gate
7. Set up Dependabot or Renovate for automated dependency updates

### Medium-term (1 month)
8. Implement cosign keyless signing for all release artifacts
9. Generate and publish SBOM for each release
10. Achieve SLSA Level 2 (signed provenance from CI platform)
11. Configure private registry to prevent dependency confusion

### Long-term (quarterly)
12. Achieve SLSA Level 3 for critical services
13. Deploy in-toto framework for end-to-end supply chain verification
14. Integrate Socket.dev or similar for real-time dependency behavior monitoring
15. Implement TUF (The Update Framework) for update security
EOF

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
- Socket.dev (`socket.dev`) provides real-time npm/PyPI behavioral analysis beyond CVE databases — recommended for high-risk projects.
- For regulated industries (FedRAMP, PCI-DSS), the generated SBOM satisfies common evidence requirements for component inventory.
