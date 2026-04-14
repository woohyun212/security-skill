# Reference: siem-rule

## Log Source to Field Mapping

| Log Source | Key Fields |
|------------|-----------|
| `windows_process_creation` | Image (process path), CommandLine, ParentImage, ParentCommandLine, User, IntegrityLevel, Hashes, OriginalFileName |
| `windows_security` | EventID, SubjectUserName, TargetUserName, LogonType, IpAddress, WorkstationName, ProcessName |
| `windows_powershell` | ScriptBlockText, Path, MessageNumber, MessageTotal |
| `linux_auditd` | syscall, exe, comm, key, uid, auid, a0, a1 |
| `cloud_aws_cloudtrail` | eventName, eventSource, userIdentity.type, userIdentity.arn, sourceIPAddress, requestParameters, responseElements |

## Log Source to Sigma Logsource Block Mapping

| Log Source Type | Sigma `logsource` Block |
|----------------|------------------------|
| `windows_process_creation` | `category: process_creation` / `product: windows` |
| `windows_registry_event` | `category: registry_event` / `product: windows` |
| `windows_network_connection` | `category: network_connection` / `product: windows` |
| `windows_powershell` | `category: ps_script` / `product: windows` |
| `windows_security` | `product: windows` / `service: security` |
| `linux_auditd` | `product: linux` / `service: auditd` |
| `cloud_aws_cloudtrail` | `product: aws` / `service: cloudtrail` |
| `cloud_azure_activity` | `product: azure` / `service: activitylogs` |

## Detection Scaffold Examples

### windows_process_creation

```yaml
detection:
    selection_main:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_suspicious:
        CommandLine|contains|all:
            - 'REPLACE_PATTERN_1'
            - 'REPLACE_PATTERN_2'
    filter_legitimate:
        ParentImage|endswith:
            - '\\REPLACE_LEGITIMATE_PARENT.exe'
    condition: selection_main and selection_suspicious and not filter_legitimate
```

### windows_security

```yaml
detection:
    selection_event:
        EventID: REPLACE_EVENT_ID
    selection_filter:
        SubjectUserName|endswith: '$'
    condition: selection_event and not selection_filter
```

### cloud_aws_cloudtrail

```yaml
detection:
    selection_main:
        eventSource: 'REPLACE_SERVICE.amazonaws.com'
        eventName:
            - 'REPLACE_API_CALL_1'
            - 'REPLACE_API_CALL_2'
    filter_authorized:
        userIdentity.arn|contains:
            - 'REPLACE_AUTHORIZED_ROLE'
    condition: selection_main and not filter_authorized
```

## Manual Platform Conversion Query Templates

### windows_process_creation

**Splunk SPL**
```spl
index=windows EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval process=lower(NewProcessName), cmdline=lower(CommandLine)
| where like(process, "%REPLACE_IMAGE%") AND like(cmdline, "%REPLACE_PATTERN%")
| table _time, host, user, process, cmdline, ParentProcessName
```

**Elastic KQL**
```
event.category:process AND event.type:start
AND process.name:("REPLACE_IMAGE")
AND process.command_line:*REPLACE_PATTERN*
AND NOT process.parent.name:("REPLACE_LEGITIMATE_PARENT")
```

**Elastic EQL**
```eql
process where event.type == "start"
  and process.name in~ ("REPLACE_IMAGE")
  and process.command_line like~ "*REPLACE_PATTERN*"
  and not process.parent.name in~ ("REPLACE_LEGITIMATE_PARENT")
```

**Sentinel KQL**
```kql
DeviceProcessEvents
| where FileName in~ ("REPLACE_IMAGE")
| where ProcessCommandLine contains "REPLACE_PATTERN"
| where not(InitiatingProcessFileName in~ ("REPLACE_LEGITIMATE_PARENT"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### windows_security

**Splunk SPL**
```spl
index=windows EventCode=REPLACE_EVENT_ID
| where NOT like(Account_Name, "%$")
| stats count by _time, host, Account_Name, Source_Network_Address
| where count > REPLACE_THRESHOLD
```

**Elastic KQL**
```
event.code:"REPLACE_EVENT_ID" AND winlog.channel:"Security"
AND NOT user.name:*$
```

**Sentinel KQL**
```kql
SecurityEvent
| where EventID == REPLACE_EVENT_ID
| where AccountType != "Machine"
| summarize count() by bin(TimeGenerated, 5m), Account, IpAddress
| where count_ > REPLACE_THRESHOLD
```

## Tactic-to-Technique Mapping (for Sigma tags)

| Technique Prefix | Tactic Tag |
|-----------------|-----------|
| T1059 | attack.execution |
| T1078 | attack.defense_evasion |
| T1055 | attack.defense_evasion |
| T1547 | attack.persistence |
| T1003 | attack.credential_access |
| T1110 | attack.credential_access |
| T1021 | attack.lateral_movement |
| T1486 | attack.impact |

## Tuning Recommendations

1. Add exceptions for known-good parent processes in `filter_*` conditions
2. Scope to monitored asset groups rather than all hosts (reduces noise 40-80%)
3. Implement time-based suppression for repeated alerts from the same host (5-min window)
4. Add risk score correlation before alerting: require `risk_score >= 60` or 2+ detections
5. Review false positive list quarterly and add new suppression rules as patterns emerge
6. Enable logging enrichment: resolve hostnames, add asset criticality tags
7. For cloud rules: whitelist automation service accounts and CI/CD IAM roles
8. For identity rules: exclude service accounts (names ending with `$`) and batch processing users

## Performance Guidance

1. Index most-selective fields first in SPL (use `tstats` for high-volume sources)
2. Use summary indexes or data models for frequently searched fields in Splunk
3. In Elasticsearch, use runtime fields sparingly; prefer mapped keyword fields
4. In Sentinel: schedule high-frequency rules no more often than every 5 minutes
5. Archive cold data beyond 90 days; hot tier should cover at least 7-14 days
6. Avoid wildcard-leading patterns (e.g., `*malware.exe`) — reverse the string instead

## Splunk RBA Enrichment Template

```spl
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
```

## Elastic ML Anomaly Job (Beaconing Detection)

```json
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
```

## Rule Lifecycle Metadata

| Stage | Meaning |
|-------|---------|
| `experimental` | New rule, unvalidated. Monitor but do not page on-call. |
| `test` | Validated in lab, running in shadow mode (no alerts fired). |
| `stable` | Production-validated, < 5% FP rate, on-call eligible. |
| `deprecated` | Superseded by better rule or threat no longer relevant. |

**Review cadence:**
- Weekly: Check alert volume and FP rate
- Monthly: Re-test against new attack variants (updated Atomic Red Team tests)
- Quarterly: Review false positive list, update filter conditions
- Annually: Full rule audit against current MITRE ATT&CK matrix version
