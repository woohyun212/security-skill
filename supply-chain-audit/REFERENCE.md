# Reference: supply-chain-audit

## SLSA Compliance Matrix

### Level Definitions

| Level | Requirements Summary |
|-------|---------------------|
| SLSA 1 | Build scripted; provenance generated |
| SLSA 2 | Build service used; provenance signed by builder |
| SLSA 3 | Hardened build platform; auditable build process |
| SLSA 4 | Hermetic, reproducible builds; two-party review |

### Current Assessment Checklist

#### SLSA Level 1
- [ ] Build process is fully scripted (no manual steps)
- [ ] Build provenance document generated (who built what, from where)
- [ ] Provenance available to consumers

#### SLSA Level 2
- [ ] Builds run on a hosted CI/CD platform (GitHub Actions, GitLab CI, etc.)
- [ ] Build provenance is signed by the build platform
- [ ] Source is version-controlled with branch protection on main
- [ ] Two-party code review required for changes to main

#### SLSA Level 3
- [ ] Build platform prevents parameter injection from source
- [ ] Build instructions cannot be influenced by untrusted input
- [ ] All transitive build dependencies are pinned by hash
- [ ] Build environment is ephemeral (no persistent state)
- [ ] Provenance is non-falsifiable (signed by hardware/HSM)

#### SLSA Level 4
- [ ] Build is hermetic (no network access during build)
- [ ] Build is reproducible bit-for-bit
- [ ] Source history is retained indefinitely
- [ ] All changes reviewed by two trusted persons

### Quick Wins (toward SLSA Level 2)

1. Pin all GitHub Actions to commit SHAs (not tags):
   `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`
2. Enable branch protection rules (require PR + review on main)
3. Add `actions/attest-build-provenance` step to release workflow
4. Use `cosign sign` with OIDC keyless signing for released artifacts

---

## Attack Surface Analysis

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

---

## Remediation Roadmap Template

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
