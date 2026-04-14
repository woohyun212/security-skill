---
name: differential-review
description: Security-focused git diff analysis to detect regressions, new vulnerabilities, and unsafe changes in code reviews
license: MIT
metadata:
  category: code-security
  locale: en
  phase: v1
---

## What this skill does

Analyzes git diffs, pull request changes, and commit ranges for security regressions. Unlike a full codebase audit, this skill focuses exclusively on what changed: additions that introduce new vulnerabilities (hardcoded secrets, injection sinks, unsafe deserialization), and removals that eliminate security controls (auth checks, input validation, rate limiting). It classifies changed files by risk tier, runs targeted pattern checks on additions and deletions, cross-references dependency changes, and produces a prioritized findings list with severity.

## When to use

- During pull request review when you need a security-focused lens on the diff specifically
- When a commit range is suspected of introducing a regression (e.g., after an incident or pentest finding)
- As a lightweight pre-merge gate before running a full `secure-code-review`
- When reviewing dependency bumps that may silently alter security behavior
- When a developer says "I only changed X" and you need to verify that claim from a security perspective

## Prerequisites

- Git access to the repository (local clone or remote diff URL)
- `git` CLI available in the environment
- (Optional) `semgrep` for automated pattern matching on additions
- Read access to dependency manifests (`package.json`, `go.mod`, `requirements.txt`, `Cargo.toml`, etc.)

## Inputs

| Item | Description | Example |
|------|-------------|---------|
| `DIFF_SOURCE` | Source of the diff to review | `git diff main..feature/login`, PR URL, patch file |
| `BASE_REF` | Base branch or commit | `main`, `v2.3.1`, `abc1234` |
| `HEAD_REF` | Target branch or commit | `feature/auth-refactor`, `HEAD`, `def5678` |
| `REPO_PATH` | Path to the local repository | `/home/user/myapp` |
| `LANGUAGE` | Primary language(s) in the diff | `Python`, `TypeScript`, `Go` |

## Workflow

### Step 1: Obtain the diff

Choose the appropriate method based on `DIFF_SOURCE`:

```bash
# Commit range
git diff <BASE_REF>..<HEAD_REF>

# Staged changes only
git diff --cached

# Specific files in a range
git diff <BASE_REF>..<HEAD_REF> -- path/to/file

# Full diff with context (recommended for security review)
git diff -U5 <BASE_REF>..<HEAD_REF>

# List only changed files for triage
git diff --name-only <BASE_REF>..<HEAD_REF>

# Include commit messages for context
git log --oneline <BASE_REF>..<HEAD_REF>
```

If working from a PR diff URL, download the raw `.diff` or `.patch` and treat it as a local file.

### Step 2: Classify changed files by risk tier

Before reading line-by-line, triage which files deserve the most attention.

**High risk — review every line of additions and deletions:**

| Signal | Examples |
|--------|---------|
| Authentication / session | `auth.py`, `login.ts`, `session_manager.go`, `jwt_util.rb` |
| Authorization / access control | `permissions.js`, `rbac.go`, `policy.py`, `middleware/auth*` |
| Cryptography | `crypto/`, `cipher.py`, `hash_util.ts`, `tls_config.go` |
| Input parsing / deserialization | `parser.py`, `deserialize.ts`, `xml_handler.go`, `yaml_loader.rb` |
| SQL / query construction | `db.py`, `queries.ts`, `repository.go`, `dao/*.java` |
| Secret / config handling | `.env*`, `config.yaml`, `secrets.ts`, `vault_client.go` |
| Dependency manifests | `package.json`, `go.mod`, `requirements.txt`, `Cargo.toml` |

**Medium risk — review additions and significant deletions:**

- HTTP route handlers and controllers
- File upload / download handlers
- External API client code
- Logging and error handling modules

**Low risk — spot-check only:**

- UI/template changes with no server-side logic
- Documentation and comments
- Pure test files (unless they reveal implementation details)
- Build scripts with no runtime impact

### Step 3: Audit additions for security anti-patterns

For each `+` line in high- and medium-risk files, check for the following. A match is a finding candidate.

**Secrets and credentials**

```
# Patterns to flag in additions
(?i)(password|passwd|secret|api_key|apikey|token|auth_token)\s*=\s*['"][^'"]{6,}['"]
(?i)(aws_access_key|aws_secret|private_key)\s*=
-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
(?i)bearer\s+[a-z0-9\-_]{20,}
```

**Injection sinks**

```
# SQL concatenation (any language)
query = "SELECT.*" + user_input
execute("INSERT INTO.*" + var)
db.query(`SELECT * FROM ${req.body`)

# Command injection
os.system(user_input)
subprocess.call(cmd, shell=True)
exec(user_controlled)
child_process.exec(req.query

# Template injection
render_template_string(user_input)   # Jinja2
new Function(userCode)               # JS
eval(expression)                     # any language
```

**Unsafe deserialization**

```
pickle.loads(data)           # Python
yaml.load(data)              # Python — safe only with Loader=yaml.SafeLoader
ObjectInputStream            # Java
JSON.parse + eval            # JS with execution
BinaryFormatter.Deserialize  # .NET
```

**Path traversal**

```
open(user_input)
os.path.join(base, user_input)   # without normalization + prefix check
fs.readFile(req.params.filename)
```

**Cryptographic weaknesses**

```
MD5 / SHA1 for password hashing or HMAC
DES / 3DES / RC4 / ECB mode
random() / Math.random() for tokens or nonces
hardcoded IV or salt
```

**If semgrep is available**, run targeted rulesets against the patch file:

```bash
semgrep --config=p/secrets --config=p/owasp-top-ten <patch_file_or_dir>
# Or against only changed files:
git diff --name-only <BASE>..<HEAD> | xargs semgrep --config=p/security-audit
```

### Step 4: Audit deletions for removed security controls

For each `-` line in high-risk files, check whether the removal eliminates a protection. A protection removal with no replacement is a finding.

**Categories to flag:**

| Removed pattern | Risk |
|----------------|------|
| Authentication middleware / decorator removed from a route | Unauthenticated access |
| Input validation / sanitization call removed | Injection or XSS vector opened |
| Rate limiting or throttle removed | Brute force / DoS exposure |
| CSRF token check removed | CSRF vulnerability |
| Authorization assertion removed (`require_permission`, `can?`, `hasRole`) | Privilege escalation |
| TLS/cert verification disabled (`verify=False`, `InsecureSkipVerify`) | MitM exposure |
| Security header removed from response | Browser-side protection lost |
| Audit log call removed | Loss of forensic visibility |
| Timeout or size limit removed | DoS / resource exhaustion |

When a protection is removed, check whether it is reinstated elsewhere in the diff (e.g., moved to a different layer). If not replaced, record as a finding.

### Step 5: Review dependency changes

Examine additions and removals in dependency manifests.

```bash
# Show only manifest changes
git diff <BASE>..<HEAD> -- package.json go.mod requirements.txt Cargo.toml pom.xml

# For npm: check advisories on newly added packages
npm audit --audit-level=moderate   # after npm install

# For Python
pip-audit   # or: safety check -r requirements.txt

# For Go
govulncheck ./...
```

Flag:

- New direct dependencies with known CVEs
- Version downgrades (could reintroduce fixed vulnerabilities)
- Pinned versions removed (hash pinning, `==x.y.z` replaced with `>=x.y`)
- New transitive dependencies that are known malicious or typosquatted

### Step 6: Produce findings

For each identified issue, record:

```markdown
### [SEVERITY] <Short title>

- **File**: `path/to/file.py:42`
- **Commit / hunk**: `abc1234` or diff hunk reference
- **Type**: Addition of vulnerable pattern | Removal of security control | Dependency risk
- **Description**: What was introduced or removed and why it is a security concern.
- **Impact**: What an attacker could achieve if exploited.
- **Remediation**: Specific fix — replace `eval(x)` with safe alternative, restore the auth check, pin the dependency version, etc.
- **References**: CWE-XX, CVE-YYYY-NNNNN (if applicable)
```

**Severity guide for differential review:**

| Severity | Criteria |
|----------|----------|
| CRITICAL | Auth bypass, RCE sink, credential leak committed to repo |
| HIGH | SQL/command injection, unsafe deserialization, removed auth check on sensitive route |
| MEDIUM | Path traversal, weak crypto introduced, rate limiting removed |
| LOW | Debug logging of sensitive data, security header removed, soft crypto downgrade |
| INFO | Style issue with minor security implication, dependency without known CVE but unmaintained |

## Done when

- All changed files are classified by risk tier
- Every addition in high- and medium-risk files has been scanned for the anti-patterns in Step 3
- Every deletion in high-risk files has been checked for removed security controls (Step 4)
- Dependency manifest changes are reviewed and advisory-checked (Step 5)
- All findings have a severity, file reference, description, impact, and remediation
- A brief summary is produced: N files changed, X high-risk, Y findings (Z CRITICAL/HIGH, W MEDIUM/LOW)

## Failure modes

| Issue | Cause | Solution |
|-------|-------|----------|
| Diff is too large to review manually | Large PR with hundreds of changed files | Triage by risk tier first; focus on CRITICAL and HIGH risk files; flag the PR for splitting |
| Diff context is insufficient to judge a deletion | `-U0` diff with no surrounding lines | Re-run `git diff -U10` or read the full function from the source tree |
| False positive on secret pattern | Test fixtures or placeholder strings | Confirm the value is not used in production config; note as INFO if test-only |
| Semgrep not available | Tooling gap | Proceed with manual pattern check; note in report that automated scan was skipped |
| Dependency manifest not present in diff | Only lock file changed | Review the lock file diff for transitive dependency changes; run `npm audit` / `pip-audit` locally |
| Renamed file appears as delete + add | Git rename detection off | Re-run `git diff -M` to detect renames; treat as a single change, not a removal |

## Notes

- This skill reviews **changes**, not the full codebase state. A vulnerability that existed before the diff and was not touched is out of scope — use `secure-code-review` for that.
- This skill pairs well with `secure-code-review` (full domain-based audit) and `secret-scan` (credential detection in diffs).
- A finding of type "removal of security control" is often more urgent than an addition finding, because it may silently expose existing functionality to attack.
- When reviewing auth-related deletions, check the commit message and linked issue for intent — accidental removals and intentional refactors look identical in a diff.
- Keep findings focused on the diff. Avoid reporting pre-existing issues unless they are directly worsened by the change.

---

Adapted from [Trail of Bits](https://github.com/trailofbits/skills) via [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills).
