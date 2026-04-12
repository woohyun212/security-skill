---
name: mitre-attack-lookup
description: MITRE ATT&CK technique, group, software, and mitigation lookup using mitrize
license: MIT
metadata:
  category: incident-response
  locale: en
  phase: v1
---

# MITRE ATT&CK Lookup

## What this skill does

Queries the MITRE ATT&CK knowledge base using [mitrize](https://github.com/woohyun212/mitrize) — a Git-based static dataset that converts STIX 2.1 JSON into individual Markdown files with YAML frontmatter. Supports technique lookup, threat actor profiling, software analysis, mitigation mapping, full-text search, and group overlap comparison. Covers Enterprise, Mobile, and ICS domains (ATT&CK v18.1+, 898 techniques, 203 groups, 929 software entries).

## When to use

- When you need to look up a specific ATT&CK technique by ID or name (e.g., T1059, "Command and Scripting Interpreter")
- When profiling a threat actor's TTPs (e.g., all techniques used by APT28 or Kimsuky)
- When mapping detected IOCs/behaviors to ATT&CK techniques during incident response
- When building detection rules and need to understand technique details and mitigations
- When comparing two threat groups to find overlapping and unique techniques
- When searching the ATT&CK knowledge base by keyword (e.g., "ransomware", "PowerShell")

## Prerequisites

- Git (to clone the mitrize repository)
- Python 3.6+ (stdlib only — no pip dependencies)
- ~100 MB disk space for the full repository

## Inputs

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `QUERY_TYPE` | Yes | Type of lookup: technique, group, software, mitigation, tactic, search, group-techniques, overlap, stats | `technique` |
| `QUERY_VALUE` | Yes | ID, name, or search keyword | `T1059`, `Kimsuky`, `ransomware` |
| `DOMAIN` | No | ATT&CK domain for direct file access (default: enterprise) | `enterprise`, `mobile`, `ics` |

## Workflow

### Step 1: Clone mitrize (first time only)

```bash
MITRIZE_DIR="${HOME}/mitrize"
if [ ! -d "$MITRIZE_DIR" ]; then
  echo "[*] Cloning mitrize repository..."
  git clone --depth 1 https://github.com/woohyun212/mitrize.git "$MITRIZE_DIR"
  echo "[+] Clone complete"
else
  echo "[*] mitrize already exists at $MITRIZE_DIR"
  cd "$MITRIZE_DIR" && git pull --ff-only 2>/dev/null
fi
```

### Step 2: Look up a technique by ID

```bash
cd "$MITRIZE_DIR"

# Using the query script (recommended)
python3 scripts/query_attack_md.py technique T1059

# Or read the file directly
cat enterprise/techniques/T1059/technique.md

# List sub-techniques
ls enterprise/techniques/T1059/
# Output: technique.md  T1059.001.md  T1059.002.md  ...

# Read a specific sub-technique
cat enterprise/techniques/T1059/T1059.001.md
```

### Step 3: Profile a threat group

```bash
cd "$MITRIZE_DIR"

# Look up group by ID or name
python3 scripts/query_attack_md.py group G0094
python3 scripts/query_attack_md.py group Kimsuky

# List all techniques used by this group, organized by tactic
python3 scripts/query_attack_md.py group-techniques G0094

# Or read the group file directly
cat enterprise/groups/G0094.md

# Extract just the technique IDs from the group file
grep -oP 'T\d{4}(\.\d{3})?' enterprise/groups/G0094.md | sort -u
```

### Step 4: Look up software/malware

```bash
cd "$MITRIZE_DIR"

# By ID or name
python3 scripts/query_attack_md.py software S0154
python3 scripts/query_attack_md.py software "Cobalt Strike"

# List all software
ls enterprise/software/
```

### Step 5: Find mitigations for a technique

```bash
cd "$MITRIZE_DIR"

# Look up mitigation by ID
python3 scripts/query_attack_md.py mitigation M1049

# Mitigations are also listed in each technique file
# under the "Mitigations" section
cat enterprise/techniques/T1059/technique.md | grep -A 20 "## Mitigations"
```

### Step 6: Search by keyword

```bash
cd "$MITRIZE_DIR"

# Full-text search across all objects
python3 scripts/query_attack_md.py search ransomware

# Or use grep for direct filesystem search
grep -rl "PowerShell" enterprise/techniques/ | head -20

# Find techniques targeting a specific platform
grep -rl '"Linux"' enterprise/techniques/ | head -20

# List all techniques in a specific tactic
python3 scripts/query_attack_md.py tactic execution
```

### Step 7: Compare two threat groups

```bash
cd "$MITRIZE_DIR"

# Show shared and unique techniques between two groups
python3 scripts/query_attack_md.py overlap G0094 G0032

# Useful for:
# - Attribution analysis (shared TTPs suggest relationship)
# - Detection prioritization (shared techniques are higher value)
# - Threat hunting (if you hunt for group A, check group B's unique techniques too)
```

### Step 8: Check dataset stats and version

```bash
cd "$MITRIZE_DIR"

# Show ATT&CK version and object counts
python3 scripts/query_attack_md.py stats

# Check ATT&CK version history via git
git log --oneline | head -10

# Diff between versions (if multiple commits)
# git diff HEAD~1..HEAD enterprise/techniques/T1059/technique.md
```

## Done when

- The requested ATT&CK object (technique, group, software, mitigation) is retrieved and displayed
- For group profiling: all associated techniques are listed with tactic mapping
- For search: relevant matches are returned grouped by object type
- For overlap: shared and unique techniques between two groups are identified

## Failure modes

| Symptom | Cause | Solution |
|---------|-------|----------|
| `FileNotFoundError` or "repo not found" | mitrize not cloned | Run `git clone https://github.com/woohyun212/mitrize.git ~/mitrize` |
| Empty result for a valid ID | Wrong domain (e.g., ICS technique searched in enterprise) | Use direct path: `cat ics/techniques/T0800/technique.md` |
| `query_attack_md.py` not finding techniques dir | Script not run from repo root | `cd ~/mitrize` before running the script |
| Outdated data | Repository not updated | `cd ~/mitrize && git pull` |
| Technique ID not found | Deprecated or revoked technique | Check ATT&CK changelog or search by name instead |

## Notes

- mitrize uses Git history for ATT&CK versioning — each ATT&CK release is a commit. Use `git diff` to see what changed between versions.
- The `query_attack_md.py` script uses Python stdlib only — zero pip dependencies.
- For Mobile and ICS domains, use direct file paths (`mobile/techniques/`, `ics/techniques/`) since the query script defaults to Enterprise.
- Cross-references between objects are relative Markdown links — follow them to traverse relationships (e.g., from a group to its techniques to their mitigations).
- This skill pairs well with `siem-rule` (map ATT&CK techniques to detection rules), `threat-model` (identify relevant techniques per system), and `ioc-extract` (map IOCs to TTPs).
- Data is sourced from [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) under CC BY 4.0 license.
