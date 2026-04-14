---
name: siem-rule
description: Create and convert SIEM detection rules (Sigma/Splunk SPL/Elastic KQL/Sentinel KQL) from threat objectives, IOCs, or CVE reports
license: MIT
metadata:
  category: incident-response
  locale: en
  phase: v1
---

## What this skill does

Guides the full lifecycle of a SIEM detection rule: define the threat objective, identify required log sources, write a platform-agnostic Sigma rule, convert it to Splunk SPL, Elastic KQL/EQL, and Microsoft Sentinel KQL, validate against test data, and document tuning recommendations. Covers endpoint, network, identity, and cloud detection categories.

## When to use

- Building new detections from a threat model, IOC, or observed TTP
- Converting an existing Sigma rule to a platform-specific query
- Auditing existing rules for performance, fidelity, or coverage gaps
- Responding to a new CVE or threat actor report and needing a fast rule
- Reducing alert fatigue by tuning false-positive-heavy detections

## Prerequisites

- `sigma-cli` for rule conversion: `pip install sigma-cli`
- Sigma backends: `sigma plugin install splunk elastic-lucene microsoft365defender`
- `python3` for validation and formatting helpers
- `jq` for JSON manipulation: `sudo apt install jq`
- Access to at least one SIEM platform (Splunk / Elastic / Sentinel) or sample log data

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `DETECTION_OBJECTIVE` | One-sentence description of what to detect | `"Detect PowerShell downloading and executing in-memory payloads"` |
| `LOG_SOURCE_TYPE` | Primary log source type | `windows_process_creation` |
| `MITRE_TECHNIQUE` | MITRE ATT&CK technique ID (optional) | `T1059.001` |
| `SIGMA_RULE_FILE` | Existing Sigma YAML file to convert (optional) | `/tmp/rule.yml` |
| `TEST_LOG_FILE` | Sample log file for validation (optional) | `/tmp/test_events.json` |

## Workflow

### Step 1: Define the detection objective

```bash
echo "=== Step 1: Define Detection Objective ==="

DETECTION_OBJECTIVE="${DETECTION_OBJECTIVE:-}"
MITRE_TECHNIQUE="${MITRE_TECHNIQUE:-}"

if [ -z "$DETECTION_OBJECTIVE" ]; then
    read -rp "What threat behavior do you want to detect? " DETECTION_OBJECTIVE
fi

if [ -z "$MITRE_TECHNIQUE" ]; then
    read -rp "MITRE ATT&CK technique ID (leave blank to skip): " MITRE_TECHNIQUE
fi

echo ""
echo "  Objective:        $DETECTION_OBJECTIVE"
echo "  MITRE technique:  ${MITRE_TECHNIQUE:-N/A}"
echo ""

# Suggest detection category based on objective keywords
python3 - "$DETECTION_OBJECTIVE" <<'PYEOF'
import sys, re

obj = sys.argv[1].lower()

categories = {
    'Endpoint – Process Creation':    ['powershell', 'cmd', 'wscript', 'mshta', 'rundll32', 'regsvr32',
                                       'process', 'spawn', 'execute', 'launch', 'child'],
    'Endpoint – Registry':            ['registry', 'regedit', 'hklm', 'hkcu', 'run key', 'persistence'],
    'Endpoint – DLL / Code Injection':['inject', 'dll', 'reflective', 'shellcode', 'virtualalloc', 'writeprocessmemory'],
    'Endpoint – PowerShell / Script': ['powershell', 'script', 'iex', 'invoke-expression', 'base64', 'bypass'],
    'Network – DNS':                  ['dns', 'tunnel', 'dga', 'domain generation', 'exfil'],
    'Network – Lateral Movement':     ['smb', 'rdp', 'wmi', 'lateral', 'pass the hash', 'psexec'],
    'Identity – Brute Force':         ['brute', 'password spray', 'login failure', 'authentication'],
    'Identity – Kerberos':            ['kerberoast', 'dcsync', 'golden ticket', 'silver ticket', 'kerberos'],
    'Cloud – IAM':                    ['iam', 'policy', 'privilege', 'assume role', 'access key'],
    'Cloud – Storage':                ['s3', 'blob', 'bucket', 'public access', 'storage'],
}

matched = []
for cat, keywords in categories.items():
    if any(kw in obj for kw in keywords):
        matched.append(cat)

if matched:
    print(f"  Suggested category: {matched[0]}")
    if len(matched) > 1:
        print(f"  Also relevant:      {', '.join(matched[1:])}")
else:
    print("  Category: General endpoint/network (review log sources in Step 2)")
PYEOF
```

### Step 2: Identify required log sources

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full log-source-to-field mapping table and logsource-to-Sigma-block mapping.

```bash
echo ""
echo "=== Step 2: Identify Log Sources ==="

LOG_SOURCE_TYPE="${LOG_SOURCE_TYPE:-}"
if [ -z "$LOG_SOURCE_TYPE" ]; then
    cat <<'LOGSOURCES'
  Common log source types:
    windows_process_creation   — Sysmon Event ID 1 / Windows Security 4688
    windows_registry_event     — Sysmon Event IDs 12/13/14
    windows_network_connection — Sysmon Event ID 3
    windows_file_event         — Sysmon Event ID 11
    windows_powershell         — Microsoft-Windows-PowerShell/4104 (Script Block)
    windows_security           — Windows Security Event Log (4624, 4625, 4768, etc.)
    windows_dns_query          — Sysmon Event ID 22
    linux_auditd               — auditd syscall / execve records
    linux_syslog               — /var/log/syslog or /var/log/auth.log
    cloud_aws_cloudtrail       — AWS CloudTrail API events
    cloud_azure_activity       — Azure Activity Log / Azure AD Sign-in
    cloud_gcp_audit            — GCP Cloud Audit Logs
    network_firewall           — Palo Alto / Fortinet / pfSense firewall logs
    network_proxy              — Squid / Zscaler / Bluecoat proxy logs
    network_dns                — BIND / Windows DNS server logs
LOGSOURCES
    read -rp "  Enter log source type: " LOG_SOURCE_TYPE
fi

echo ""
echo "  Selected log source: $LOG_SOURCE_TYPE"

python3 - "$LOG_SOURCE_TYPE" <<'PYEOF'
import sys

fields = {
    'windows_process_creation': [
        'Image (process path)', 'CommandLine', 'ParentImage', 'ParentCommandLine',
        'User', 'IntegrityLevel', 'Hashes', 'OriginalFileName',
    ],
    'windows_security': [
        'EventID', 'SubjectUserName', 'TargetUserName', 'LogonType',
        'IpAddress', 'WorkstationName', 'ProcessName',
    ],
    'windows_powershell': ['ScriptBlockText', 'Path', 'MessageNumber', 'MessageTotal'],
    'linux_auditd': ['syscall', 'exe', 'comm', 'key', 'uid', 'auid', 'a0', 'a1'],
    'cloud_aws_cloudtrail': [
        'eventName', 'eventSource', 'userIdentity.type', 'userIdentity.arn',
        'sourceIPAddress', 'requestParameters', 'responseElements',
    ],
}

src = sys.argv[1]
known = fields.get(src)
if known:
    print(f"\n  Key fields for {src}:")
    for f in known:
        print(f"    - {f}")
else:
    print(f"\n  No field reference available for '{src}' — consult vendor documentation.")
PYEOF
```

### Step 3: Write the Sigma rule

> **Reference**: See [REFERENCE.md](REFERENCE.md) for detection scaffold examples per log source type.

```bash
echo ""
echo "=== Step 3: Write Sigma Rule ==="

SIGMA_RULE_FILE="${SIGMA_RULE_FILE:-}"
RULE_OUTPUT="/tmp/siem_rule_$(date +%s).yml"

if [ -n "$SIGMA_RULE_FILE" ] && [ -f "$SIGMA_RULE_FILE" ]; then
    echo "  [+] Using existing Sigma rule: $SIGMA_RULE_FILE"
    RULE_OUTPUT="$SIGMA_RULE_FILE"
else
    # See REFERENCE.md for the full Sigma rule generator script.
    # Run with: python3 <(extract sigma-generator from REFERENCE.md) \
    #   "$DETECTION_OBJECTIVE" "$LOG_SOURCE_TYPE" "$MITRE_TECHNIQUE" "$RULE_OUTPUT"
    echo "  [!] Replace all REPLACE_* placeholders with real values before proceeding."
    echo "  [*] See REFERENCE.md for logsource-to-Sigma-block and detection scaffold examples."
fi

echo ""
echo "  Sigma rule file: $RULE_OUTPUT"
```

### Step 4: Convert to platform-specific queries

> **Reference**: See [REFERENCE.md](REFERENCE.md) for manual platform conversion query templates (Splunk SPL, Elastic KQL/EQL, Sentinel KQL) and the Splunk RBA enrichment template.

```bash
echo ""
echo "=== Step 4: Platform Conversion ==="

RULE_FILE="$RULE_OUTPUT"

if command -v sigma &>/dev/null; then
    echo ""
    echo "[Splunk SPL]"
    sigma convert -t splunk -p splunk_windows "$RULE_FILE" 2>/dev/null || \
        sigma convert -t splunk "$RULE_FILE" 2>/dev/null || \
        echo "  [!] Conversion failed — install backend: sigma plugin install splunk"

    echo ""
    echo "[Elastic KQL]"
    sigma convert -t elasticsearch -p ecs_windows "$RULE_FILE" 2>/dev/null || \
        sigma convert -t elasticsearch "$RULE_FILE" 2>/dev/null || \
        echo "  [!] Conversion failed — install backend: sigma plugin install elasticsearch"

    echo ""
    echo "[Elastic EQL]"
    sigma convert -t elasticsearch -p ecs_windows -f eql "$RULE_FILE" 2>/dev/null || \
        echo "  [!] EQL conversion not available for this backend version"

    echo ""
    echo "[Microsoft Sentinel KQL]"
    sigma convert -t microsoft365defender "$RULE_FILE" 2>/dev/null || \
        sigma convert -t azure-monitor "$RULE_FILE" 2>/dev/null || \
        echo "  [!] Conversion failed — install backend: sigma plugin install microsoft365defender"
else
    echo "  [!] sigma-cli not installed. Run: pip install sigma-cli"
    echo "      Then install backends:"
    echo "        sigma plugin install splunk"
    echo "        sigma plugin install elasticsearch"
    echo "        sigma plugin install microsoft365defender"
    echo ""
    echo "  [*] See REFERENCE.md for manual conversion query templates."
fi
```

### Step 5: Validate with test data

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the structural log-validation script (field-match validator against JSONL test events).

```bash
echo ""
echo "=== Step 5: Validate Rule ==="

TEST_LOG_FILE="${TEST_LOG_FILE:-}"

if [ -n "$TEST_LOG_FILE" ] && [ -f "$TEST_LOG_FILE" ]; then
    echo "  [*] Run the validation script from REFERENCE.md against $TEST_LOG_FILE and $RULE_OUTPUT"
    echo "  NOTE: Use sigma-test or platform-native replay for accurate validation."
else
    echo "  [*] No TEST_LOG_FILE provided — skipping automated validation."
    echo ""
    echo "  Manual validation checklist:"
    echo "    [ ] Generate TP events: Invoke-AtomicTest T1059.001 -TestNumbers 1"
    echo "    [ ] Replay events against SIEM and confirm rule fires"
    echo "    [ ] Run query over 7-30 days of production data to check FP rate"
    echo "    [ ] Target < 10 alerts/day for high-severity rules"
    echo "    [ ] Validate filter conditions suppress known-good activity"
    echo "    [ ] Test encoded and plaintext variants of the attack pattern"
fi
```

### Step 6: Document tuning recommendations

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the full tuning recommendations list, performance guidance, and rule lifecycle metadata.

```bash
echo ""
echo "=== Step 6: Tuning Recommendations ==="

python3 - "$RULE_OUTPUT" <<'PYEOF'
import sys, yaml, os

rule_file = sys.argv[1]
rule_name = os.path.basename(rule_file)

try:
    with open(rule_file) as f:
        rule = yaml.safe_load(f)
    title = rule.get('title', rule_name)
    level = rule.get('level', 'unknown')
    fps   = rule.get('falsepositives', [])
except Exception:
    title = rule_name
    level = 'unknown'
    fps   = []

print(f"  Rule: {title}")
print(f"  Severity: {level}")
print()

if fps:
    print("  [Known false positive sources]")
    for fp in fps:
        print(f"    - {fp}")

print()
print("  See REFERENCE.md for full tuning recommendations and performance guidance.")
PYEOF

echo ""
echo "[+] Sigma rule:  $RULE_OUTPUT"
echo "[+] To convert manually: sigma convert -t <backend> $RULE_OUTPUT"
echo "[*] See REFERENCE.md for Elastic ML anomaly job and RBA enrichment templates."
```

## Done when

- Sigma rule YAML is written and saved without placeholder values
- At least one platform-specific query (SPL/KQL/EQL) is generated or printed
- Rule has been validated against test data or manual checklist is documented
- Tuning recommendations are reviewed and filter conditions are added for known FPs
- Rule metadata (MITRE ATT&CK tags, severity, author, date) is complete

## Failure modes

| Problem | Cause | Solution |
|---------|-------|----------|
| `sigma: command not found` | sigma-cli not installed | `pip install sigma-cli` |
| Backend plugin missing | Not installed | `sigma plugin install <backend>` |
| `yaml.safe_load` error | Malformed YAML | Validate with `python3 -c "import yaml; yaml.safe_load(open('rule.yml'))"` |
| High false positive rate | Overly broad patterns | Add `filter_*` conditions in Sigma detection block |
| No test log data | Missing sample events | Use Atomic Red Team or download samples from sigma-test fixtures |
| Sentinel rule deployment fails | ARM template validation error | Use Azure portal > Sentinel > Analytics > Import rule |

## Notes

- Sigma is the recommended source-of-truth format. Always write Sigma first, then convert.
- The `sigmac` legacy tool is deprecated; use `sigma-cli` (maintained by SigmaHQ).
- Community Sigma rule repository: https://github.com/SigmaHQ/sigma
- Elastic detection rules repository: https://github.com/elastic/detection-rules
- Splunk Security Content: https://research.splunk.com/
- For bulk rule deployment, use Splunk's `escu` app or Elastic's `detection-rules` CLI.
- Generated rules are scaffolds — test every rule in a staging environment before production.
- Cross-reference new rules with the `log-analysis` skill to backtest against existing logs.
