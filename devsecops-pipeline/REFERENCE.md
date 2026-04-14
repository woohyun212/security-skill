# Reference: devsecops-pipeline

## GitHub Actions Workflow Template

Full DevSecOps pipeline covering secrets scan, SAST (Semgrep + CodeQL), SCA (Trivy), IaC scan (Checkov), container scan, DAST (ZAP), and SBOM generation with cosign signing.

Save as `.github/workflows/devsecops-pipeline.yml` in your repository and adjust the language matrix, severity thresholds, and `vars.DAST_TARGET_URL` before committing.

```yaml
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
```

---

## GitLab CI Snippet

Add to your `.gitlab-ci.yml` via `include: - local: gitlab-devsecops.yml`.

```yaml
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
```

---

## Security Gate Policy Tables

### Hard Gates (block merge/deploy on failure)

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

### Soft Gates (warn; require documented exception)

| Gate | Condition | Tool |
|------|-----------|------|
| High SAST finding | CVSS 7.0–8.9 in new code | Semgrep |
| High dependency CVE | CVSS 7.0–8.9 in transitive deps | Trivy |
| Dockerfile best-practice violation | hadolint DL* rules | hadolint |
| License compliance | Copyleft license in dependency | Trivy / FOSSA |

### Metrics Targets

| Metric | Target |
|--------|--------|
| Vulnerabilities introduced per sprint | < 2 high, 0 critical |
| Mean Time to Detect (MTTD) | < 24 hours |
| Mean Time to Remediate (MTTR) critical | < 48 hours |
| False positive rate (SAST) | < 15% |
| Pipeline security coverage | 100% of repos |
| SBOM freshness | Generated on every release |

---

## Implementation Roadmap

### Phase 1 — Foundation (Week 1–2)
- [ ] Enable gitleaks pre-commit hook (`gitleaks protect --staged`)
- [ ] Add SAST job (Semgrep `p/ci` ruleset) to existing CI pipeline
- [ ] Enable Dependabot / renovate for dependency updates
- [ ] Integrate Trivy filesystem scan with HIGH/CRITICAL gate

### Phase 2 — Build hardening (Week 3–4)
- [ ] Add CodeQL for primary application language
- [ ] Add Checkov IaC scan if Terraform/Kubernetes present
- [ ] Add container image scan (Trivy or Grype) to build stage
- [ ] Configure SonarQube/SonarCloud for code quality + security

### Phase 3 — Test & Release (Week 5–6)
- [ ] Deploy OWASP ZAP baseline scan against staging environment
- [ ] Generate SBOM (CycloneDX) on every release branch merge
- [ ] Implement cosign keyless signing for release images
- [ ] Add Nuclei scan for known CVE/misconfiguration templates

### Phase 4 — Operate & Monitor (Week 7–8)
- [ ] Deploy Falco to Kubernetes clusters with default ruleset
- [ ] Enable CSPM (AWS Security Hub / GCP SCC / Azure Defender)
- [ ] Connect pipeline findings to SIEM (Splunk / Elastic)
- [ ] Establish vulnerability dashboard and MTTR tracking

### Phase 5 — Mature (Ongoing)
- [ ] Tune SAST rulesets to reduce false positives below 15%
- [ ] Implement IAST agent for integration test environments
- [ ] Enforce policy-as-code via OPA Gatekeeper (Kubernetes)
- [ ] Quarterly threat modeling sessions per STRIDE methodology
- [ ] Achieve SLSA Level 2+ for critical services

---

## Gap Analysis Table

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
