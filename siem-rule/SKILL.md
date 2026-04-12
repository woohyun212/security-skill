---
name: siem-rule
description: SIEM detection rule engineering for Sigma, Splunk, Elastic, and Sentinel
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

# Print field reference for chosen log source
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

```bash
echo ""
echo "=== Step 3: Write Sigma Rule ==="

SIGMA_RULE_FILE="${SIGMA_RULE_FILE:-}"
RULE_OUTPUT="/tmp/siem_rule_$(date +%s).yml"

if [ -n "$SIGMA_RULE_FILE" ] && [ -f "$SIGMA_RULE_FILE" ]; then
    echo "  [+] Using existing Sigma rule: $SIGMA_RULE_FILE"
    RULE_OUTPUT="$SIGMA_RULE_FILE"
else
    # Generate Sigma rule scaffold
    python3 - "$DETECTION_OBJECTIVE" "$LOG_SOURCE_TYPE" "$MITRE_TECHNIQUE" "$RULE_OUTPUT" <<'PYEOF'
import sys, uuid, datetime, re

objective    = sys.argv[1]
log_source   = sys.argv[2]
mitre_tech   = sys.argv[3]
output_path  = sys.argv[4]

rule_id = str(uuid.uuid4())
date    = datetime.datetime.utcnow().strftime('%Y/%m/%d')

# Map log source to Sigma logsource block
logsource_map = {
    'windows_process_creation': "    category: process_creation\n    product: windows",
    'windows_registry_event':   "    category: registry_event\n    product: windows",
    'windows_network_connection':"    category: network_connection\n    product: windows",
    'windows_powershell':       "    category: ps_script\n    product: windows",
    'windows_security':         "    product: windows\n    service: security",
    'linux_auditd':             "    product: linux\n    service: auditd",
    'cloud_aws_cloudtrail':     "    product: aws\n    service: cloudtrail",
    'cloud_azure_activity':     "    product: azure\n    service: activitylogs",
}
logsource_block = logsource_map.get(log_source,
    f"    category: REPLACE_CATEGORY\n    product: REPLACE_PRODUCT")

# Build detection scaffold based on log source
detection_examples = {
    'windows_process_creation': (
        "    selection_main:\n"
        "        Image|endswith:\n"
        "            - '\\\\powershell.exe'\n"
        "            - '\\\\pwsh.exe'\n"
        "    selection_suspicious:\n"
        "        CommandLine|contains|all:\n"
        "            - 'REPLACE_PATTERN_1'\n"
        "            - 'REPLACE_PATTERN_2'\n"
        "    filter_legitimate:\n"
        "        ParentImage|endswith:\n"
        "            - '\\\\REPLACE_LEGITIMATE_PARENT.exe'\n"
        "    condition: selection_main and selection_suspicious and not filter_legitimate"
    ),
    'windows_security': (
        "    selection_event:\n"
        "        EventID: REPLACE_EVENT_ID\n"
        "    selection_filter:\n"
        "        SubjectUserName|endswith: '$'\n"
        "    condition: selection_event and not selection_filter"
    ),
    'cloud_aws_cloudtrail': (
        "    selection_main:\n"
        "        eventSource: 'REPLACE_SERVICE.amazonaws.com'\n"
        "        eventName:\n"
        "            - 'REPLACE_API_CALL_1'\n"
        "            - 'REPLACE_API_CALL_2'\n"
        "    filter_authorized:\n"
        "        userIdentity.arn|contains:\n"
        "            - 'REPLACE_AUTHORIZED_ROLE'\n"
        "    condition: selection_main and not filter_authorized"
    ),
}

detection_block = detection_examples.get(log_source,
    "    selection:\n        REPLACE_FIELD: 'REPLACE_VALUE'\n    condition: selection")

# MITRE tags
tags_block = ""
if mitre_tech:
    tactic_map = {
        'T1059': 'attack.execution', 'T1078': 'attack.defense_evasion',
        'T1055': 'attack.defense_evasion', 'T1547': 'attack.persistence',
        'T1003': 'attack.credential_access', 'T1110': 'attack.credential_access',
        'T1021': 'attack.lateral_movement', 'T1486': 'attack.impact',
    }
    tactic = tactic_map.get(mitre_tech[:5], 'attack.REPLACE_TACTIC')
    tags_block = f"tags:\n    - {tactic}\n    - attack.{mitre_tech.lower()}\n"

sigma_rule = f"""title: {objective[:80]}
id: {rule_id}
status: experimental
description: |
    {objective}
    Generated by siem-rule skill. Review and tune before production deployment.
author: siem-rule skill
date: {date}
references:
    - https://attack.mitre.org/techniques/{mitre_tech.replace('.','/')}/ 
{tags_block}logsource:
{logsource_block}
detection:
{detection_block}
falsepositives:
    - Legitimate administrative activity
    - Authorized scripts matching pattern
level: medium
"""

with open(output_path, 'w') as f:
    f.write(sigma_rule)

print(f"  [+] Sigma rule scaffold written to: {output_path}")
print()
print(sigma_rule)
print("  [!] Replace all REPLACE_* placeholders with real values before proceeding.")
PYEOF
fi

echo ""
echo "  Sigma rule file: $RULE_OUTPUT"
```

### Step 4: Convert to platform-specific queries

#### Step 4a: Convert with sigma-cli

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
    echo "  [*] Manual conversion reference:"
    python3 - "$LOG_SOURCE_TYPE" <<'PYEOF'
import sys

src = sys.argv[1]

guides = {
    'windows_process_creation': {
        'Splunk SPL': (
            'index=windows EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n'
            '| eval process=lower(NewProcessName), cmdline=lower(CommandLine)\n'
            '| where like(process, "%REPLACE_IMAGE%") AND like(cmdline, "%REPLACE_PATTERN%")\n'
            '| table _time, host, user, process, cmdline, ParentProcessName'
        ),
        'Elastic KQL': (
            'event.category:process AND event.type:start\n'
            'AND process.name:("REPLACE_IMAGE")\n'
            'AND process.command_line:*REPLACE_PATTERN*\n'
            'AND NOT process.parent.name:("REPLACE_LEGITIMATE_PARENT")'
        ),
        'Elastic EQL': (
            'process where event.type == "start"\n'
            '  and process.name in~ ("REPLACE_IMAGE")\n'
            '  and process.command_line like~ "*REPLACE_PATTERN*"\n'
            '  and not process.parent.name in~ ("REPLACE_LEGITIMATE_PARENT")'
        ),
        'Sentinel KQL': (
            'DeviceProcessEvents\n'
            '| where FileName in~ ("REPLACE_IMAGE")\n'
            '| where ProcessCommandLine contains "REPLACE_PATTERN"\n'
            '| where not(InitiatingProcessFileName in~ ("REPLACE_LEGITIMATE_PARENT"))\n'
            '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName'
        ),
    },
    'windows_security': {
        'Splunk SPL': (
            'index=windows EventCode=REPLACE_EVENT_ID\n'
            '| where NOT like(Account_Name, "%$")\n'
            '| stats count by _time, host, Account_Name, Source_Network_Address\n'
            '| where count > REPLACE_THRESHOLD'
        ),
        'Elastic KQL': (
            'event.code:"REPLACE_EVENT_ID" AND winlog.channel:"Security"\n'
            'AND NOT user.name:*$'
        ),
        'Sentinel KQL': (
            'SecurityEvent\n'
            '| where EventID == REPLACE_EVENT_ID\n'
            '| where AccountType != "Machine"\n'
            '| summarize count() by bin(TimeGenerated, 5m), Account, IpAddress\n'
            '| where count_ > REPLACE_THRESHOLD'
        ),
    },
}

platform_map = guides.get(src, {})
if platform_map:
    for platform, query in platform_map.items():
        print(f"\n  [{platform}]")
        for line in query.split('\n'):
            print(f"    {line}")
else:
    print(f"\n  No template available for '{src}'. Refer to sigma-cli docs.")
PYEOF
fi
```

#### Step 4b: Enrich Splunk query with Risk-Based Alerting (RBA)

```bash
echo ""
echo "[Splunk RBA enrichment template]"
cat <<'RBA_TEMPLATE'
  | eval risk_score=case(
        like(cmdline, "%-enc%") OR like(cmdline, "%-EncodedCommand%"), 80,
        like(cmdline, "%-nop%") OR like(cmdline, "%-NonInteractive%"),  60,
        true(), 40
    ),
    risk_object=user,
    risk_object_type="user",
    threat_object=process,
    threat_object_type="process"
  | risk altKey=$risk_object$ altType=$risk_object_type$ score=$risk_score$
    threats=REPLACE_THREAT_NAME confidence=80 impact=60
RBA_TEMPLATE
```

#### Step 4c: Elastic ML anomaly job reference

```bash
echo ""
echo "[Elastic ML job reference]"
cat <<'ML_TEMPLATE'
  For beaconing / periodic C2 detection:
    PUT _ml/anomaly_detectors/network_beaconing
    {
      "description": "Detect periodic network connections (beaconing)",
      "analysis_config": {
        "bucket_span": "15m",
        "detectors": [{
          "detector_description": "low_count partitionfield=destination.ip",
          "function": "low_count",
          "partition_field_name": "destination.ip"
        }],
        "influencers": ["source.ip", "destination.ip", "destination.port"]
      },
      "data_description": { "time_field": "@timestamp" },
      "datafeed_config": {
        "indices": ["logs-network.*"],
        "query": { "match_all": {} }
      }
    }
ML_TEMPLATE
```

### Step 5: Validate with test data

```bash
echo ""
echo "=== Step 5: Validate Rule ==="

TEST_LOG_FILE="${TEST_LOG_FILE:-}"

if [ -n "$TEST_LOG_FILE" ] && [ -f "$TEST_LOG_FILE" ]; then
    python3 - "$TEST_LOG_FILE" "$RULE_OUTPUT" <<'PYEOF'
import sys, json, re, yaml

log_file  = sys.argv[1]
rule_file = sys.argv[2]

print(f"  Validating rule against: {log_file}")

try:
    with open(rule_file) as f:
        rule = yaml.safe_load(f)
except Exception as e:
    print(f"  [!] Could not parse Sigma YAML: {e}")
    sys.exit(1)

detection = rule.get('detection', {})

# Load test events
events = []
with open(log_file, errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({'raw': line})

# Naive field-match validator (not a full Sigma engine)
matched = 0
for event in events:
    event_str = json.dumps(event).lower()
    for key, value in detection.items():
        if key in ('condition', 'filter_legitimate', 'filter_authorized'):
            continue
        if isinstance(value, dict):
            for field, pattern in value.items():
                if field == 'EventID' and isinstance(pattern, int):
                    if str(pattern) in event_str:
                        matched += 1
                elif isinstance(pattern, list):
                    if any(str(p).lower().strip('%') in event_str for p in pattern):
                        matched += 1
                elif isinstance(pattern, str):
                    if pattern.lower().strip('*%') in event_str:
                        matched += 1

print(f"  Total events: {len(events)}")
print(f"  Matched events: {matched}")
if len(events) > 0:
    fpr_estimate = matched / len(events)
    print(f"  Match rate: {fpr_estimate:.1%} "
          f"({'[!] HIGH — tune filter conditions' if fpr_estimate > 0.1 else '[OK] acceptable'  })")
else:
    print("  [!] No events loaded from test file.")
print("")
print("  NOTE: This is a structural validator only.")
print("        Use sigma-test or platform-native replay for accurate validation.")
PYEOF
else
    echo "  [*] No TEST_LOG_FILE provided — skipping automated validation."
    echo ""
    echo "  Manual validation checklist:"
    cat <<'VALIDATION'
    [ ] Generate true-positive test events using Atomic Red Team:
          Invoke-AtomicTest T1059.001 -TestNumbers 1
    [ ] Replay events against SIEM and confirm rule fires
    [ ] Check for false positives by running query over 7-30 days of production data
    [ ] Measure alert volume: target < 10 alerts/day for high-severity rules
    [ ] Validate all filter conditions suppress known-good activity
    [ ] Test with both encoded and plaintext variants of the attack pattern
VALIDATION
fi
```

### Step 6: Document tuning recommendations

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
print("  [Tuning recommendations]")

recommendations = [
    "Add exceptions for known-good parent processes in filter_* conditions",
    "Scope to monitored asset groups rather than all hosts (reduces noise 40-80%)",
    "Implement time-based suppression for repeated alerts from the same host (5-min window)",
    "Add risk score correlation before alerting: require risk_score >= 60 or 2+ detections",
    "Review false positive list quarterly and add new suppression rules as patterns emerge",
    "Enable logging enrichment: resolve hostnames, add asset criticality tags",
    "For cloud rules: whitelist automation service accounts and CI/CD IAM roles",
    "For identity rules: exclude service accounts (names ending with $) and batch processing users",
]

for i, rec in enumerate(recommendations, 1):
    print(f"  {i}. {rec}")

print()
print("  [Performance guidance]")
perf = [
    "Index most-selective fields first in SPL (use tstats for high-volume sources)",
    "Use summary indexes or data models for frequently searched fields in Splunk",
    "In Elasticsearch, use runtime fields sparingly; prefer mapped keyword fields",
    "In Sentinel: schedule high-frequency rules no more often than every 5 minutes",
    "Archive cold data beyond 90 days; hot tier should cover at least 7-14 days",
    "Avoid wildcard-leading patterns (e.g., *malware.exe) — reverse the string instead",
]

for i, tip in enumerate(perf, 1):
    print(f"  {i}. {tip}")

if fps:
    print()
    print("  [Known false positive sources]")
    for fp in fps:
        print(f"    - {fp}")
PYEOF

echo ""
echo "[Rule lifecycle metadata]"
cat <<'LIFECYCLE'
  Maturity stages:
    experimental  → New rule, unvalidated. Monitor but do not page on-call.
    test          → Validated in lab, running in shadow mode (no alerts fired).
    stable        → Production-validated, < 5% FP rate, on-call eligible.
    deprecated    → Superseded by better rule or threat no longer relevant.

  Review cadence:
    - Weekly:    Check alert volume and FP rate
    - Monthly:   Re-test against new attack variants (updated Atomic Red Team tests)
    - Quarterly: Review false positive list, update filter conditions
    - Annually:  Full rule audit against current MITRE ATT&CK matrix version
LIFECYCLE

echo ""
echo "[+] Sigma rule:  $RULE_OUTPUT"
echo "[+] To convert manually: sigma convert -t <backend> $RULE_OUTPUT"
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
