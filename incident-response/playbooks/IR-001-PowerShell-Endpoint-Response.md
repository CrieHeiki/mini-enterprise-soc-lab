# IR-001 — Suspicious PowerShell Execution, Run-Key Modification & Network Activity

**Project:** Mini Enterprise SOC — Wazuh / Windows Endpoint & Active Directory Detection<br>
**Document version:** 1.0 | **Status:** Lab playbook (not an organizationally approved production procedure)<br>
**Owner / primary handler:** SOC Tier 1 | **Approver for containment:** SOC L2 / Incident Commander / asset owner (per organization policy)<br>
**Trigger:** `ENDPOINT_MULTISTAGE_POWERSHELL`, Wazuh rule `100410` (level 10)<br>
**Validated lab case:** [CASE-001](../../incident-reports/CASE-001/CASE-001-Endpoint-PowerShell-Investigation.md) — finding `fe92e604e9d2a74957559197`<br>
**Reference:** NIST SP 800-61 Rev. 3 (Detect / Respond / Recover); MITRE ATT&CK T1059.001 and T1547.001.

> **Purpose:** Guide a Tier 1 analyst from a correlated Wazuh alert to evidence preservation, context-aware disposition, and handoff. **Do not confuse a behavioral true positive with a confirmed compromise.** This document contains read-only investigation commands. Potentially disruptive actions require authorization and are deliberately *not* automated here.

## 0. First response and role boundaries

1. Open a case/ticket; record analyst, first-seen time, finding ID, rule ID, Wazuh link, affected source agent, reported severity, lab/production scope.
2. Verify whether this is a pre-approved test. Confirm **who authorized it, purpose, timeframe, source endpoint and expected destinations**; `data.integration_test=false` only means not marked as adapter replay.
3. L1 may **triage, query, export, correlate, hash, document and escalate**. L1 must not independently terminate processes, remove registry values, quarantine files, isolate the machine, alter firewall rules, rotate credentials or reboot.
4. If a live compromise is plausible, **escalate immediately** while preserving telemetry; do not wait to finish every check before raising the incident.

## 1. Intake: verify the Wazuh finding

**Discover:** Index `wazuh-alerts-*`; DQL: `rule.id: "100410"`; time range covering the observation. Display `timestamp`, `rule.id`, `rule.level`, `data.soclab_detection`, `data.finding_id`, `data.agent_id`, `data.agent_name`, `data.integration_test`, `data.evidence_event_ids`.

**For the validated lab case:**

| Field | Expected from collected evidence |
|---|---|
| `data.finding_id` | `fe92e604e9d2a74957559197` |
| `data.agent_id`, `data.agent_name` | `001`, `WIN10-ENDPOINT01` |
| `data.soclab_detection` | `ENDPOINT_MULTISTAGE_POWERSHELL` |
| `data.evidence_event_ids` | `1,3,13` |
| Source Windows hostname | `CRIE2910` |
| `data.integration_test` | `false` for this *controlled simulation* |

**Important:** The top-level Wazuh `agent.id=000` / `agent.name=WAZUH-SIEM` may describe the **Manager-local adapter log**, not the compromised endpoint. Determine the original source using `data.agent_id` and `data.agent_name`.

To confirm the finding from the Manager (read-only):

```bash
sudo jq -c 'select(.soclab_detection=="ENDPOINT_MULTISTAGE_POWERSHELL" and .finding_id=="fe92e604e9d2a74957559197")' /var/log/soclab-findings.jsonl
sudo jq -c 'select(.soclab_detection=="ENDPOINT_MULTISTAGE_POWERSHELL" and .finding_id=="fe92e604e9d2a74957559197")' /var/log/soclab-alerts.jsonl
```

A finding need not still be in today's `alerts.json` after rotation; prefer Discover or date-specific archive files for older alerts.

## 2. Evidence acquisition and preservation

Create a restricted evidence folder; preserve original JSON and do not modify the archived source:

```bash
umask 077
mkdir -p ~/SOC-Lab/incident-reports/CASE-001/evidence
cd ~/SOC-Lab/incident-reports/CASE-001
wc -l evidence/sysmon-events.jsonl
sha256sum evidence/sysmon-events.jsonl > evidence/sysmon-events.sha256
sha256sum -c evidence/sysmon-events.sha256
```

The previously extracted file should contain **three** Sysmon event records. If missing, re-extract using agent `001`, Sysmon channel, and **Record IDs 104556, 104596, 104647** from the relevant Wazuh archive; verify source file/date first. Do not manufacture event data or overwrite evidence silently. Save command history or an `extraction-notes.md` with the source path, extraction date, analyst, and checksum.

Read-only structured review:

```bash
jq -r '
  [.data.win.system.eventID,
   .data.win.system.eventRecordID,
   .data.win.system.systemTime,
   .data.win.eventdata.processGuid,
   (.data.win.eventdata.image // ""),
   (.data.win.eventdata.targetObject // ""),
   (.data.win.eventdata.destinationIp // "")]
  | @tsv
' evidence/sysmon-events.jsonl
```

**Evidence security:** Log files can include usernames, command lines, paths, tokens, and internal addresses. Retain raw evidence privately; publish **sanitized** evidence/examples only after review.

## 3. Technical triage checklist

| Check | Event / location | Analyst question |
|---|---|---|
| Process execution | Sysmon ID 1 | Exact image, parent process, user, integrity, `-EncodedCommand`, full command line? |
| Registry modification | Sysmon ID 13 | Which Run-key path/value; payload points to what executable; has it persisted? |
| Network connection | Sysmon ID 3 | Destination IP/port, internal vs external, connection ownership, related activity? |
| Correlation integrity | Sysmon ProcessGuid and agent | Do all 3 events share `ProcessGuid` and agent within 120 s? |
| Enrichment | Sysmon/PowerShell/Defender logs | Any additional process/network activity, detections, persistence, logons? |
| Test context | Change/test record | Is activity authorized and in the correct timeframe? |

Known lab evidence from CASE-001:

```text
Event 1  / Record 104556 / 2026-10-17 12:38:35.106 UTC: child powershell.exe -EncodedCommand
Event 13 / Record 104596 / 2026-10-17 12:38:36.292 UTC: HKCU Run value SOC-Lab-E2E-20261017193836 => notepad.exe
Event 3  / Record 104647 / 2026-10-17 12:38:37.403 UTC: 192.168.56.20:49873 -> 192.168.56.10:18080/TCP
ProcessGuid: {e4e2770f-6c4a-6ad3-2c01-000000002200}
```

**PowerShell encoded-command analysis:** Decode **offline/read-only** as UTF-16LE. Never `Invoke-Expression`, execute decoded content, or paste unknown commands into a shell. The known controlled script created a benign test Run key, contacted a lab-only listener, and attempted cleanup. Do not infer data exfiltration solely from Sysmon network event ID 3.

**Verify current Run key without altering it** on the *same Windows account* that ran the simulation:

```powershell
$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = 'SOC-Lab-E2E-20261017193836'
$key = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
if ($null -eq $key -or $null -eq $key.PSObject.Properties[$name]) {
    'PASS: Test Run value is absent from this user hive'
} else {
    "REVIEW: Test Run value remains: $($key.PSObject.Properties[$name].Value)"
}
```

**Caveat:** `HKCU` is the logged-in account's hive. Running as another administrator checks the *wrong* hive; resolve the original user SID (`S-1-5-21-3866759802-943638242-2602647168-1000`) if needed.

## 4. Severity and escalation decision

| Condition | L1 decision |
|---|---|
| Authorized test matches expected command, internal listener, and timeframe; cleanup verified | Document **behavioral true positive / authorized test** and request case closure according to process |
| Unknown script, destination, initiator or authorization | **Escalate to L2** with High priority; seek process-tree and endpoint investigation |
| Repeated unauthorized Run-key changes, suspicious external communication, Defender alerts | **Urgent L2/IR escalation**; consider containment after approval |
| Evidence suggests active harmful execution or multi-host compromise | Follow emergency incident escalation immediately; authorized responders decide isolation |
| Missing critical evidence or large time offset | Record as **insufficient evidence**, preserve what is available, request expanded investigation |

Severity rule `100410` = 10 is the detection level, **not** a confirmed incident severity or an automatic command to isolate.

## 5. Containment / eradication / recovery: approval-gated actions

**Only authorized L2/IR/asset owner personnel should select and execute these actions after checking safety and business impact:** isolate the Windows endpoint or block a confirmed malicious destination, stop a confirmed malicious process, disable persistence, quarantine proven malicious binaries, rotate compromised credentials, restore endpoint functionality and verify clean logs. Preserve volatile evidence when feasible **before** disruption; do not reboot or delete evidence merely to close an alert.

**Lab CASE-001:** do *not* isolate `WIN10-ENDPOINT01` simply because the controlled test triggered. Verify Run-key cleanup; retain evidence; preserve Wazuh/Sysmon/Defender collection. If the test artifact persists, request approval before removal and document the before/after state.

## 6. Escalation handoff — required minimum

Fill [HANDOFF-TEMPLATE.md](HANDOFF-TEMPLATE.md) with: alert ID/finding ID, detection time **with timezone/source**, host/agent, analyst's timeline, process GUID, command-line summary (redact secrets), registry change, destination, observed vs inferred findings, approval/testing status, suspected impact, SHA-256/evidence paths, outstanding questions, and **specific action requested**.

**For CASE-001:** mention the historical Sysmon vs Wazuh timestamp offset of approximately 74 seconds; do **not** silently rewrite original timestamps.

## 7. Closure and lessons learned

- [ ] Source alert and correlation chain verified (not just detection name)
- [ ] Lab/test authorization recorded or escalated if absent
- [ ] Three raw Sysmon events retained and SHA-256 verified
- [ ] Registry artifact state checked on correct user hive
- [ ] Related alerts checked; no unsupported C2/exfiltration conclusions
- [ ] Historical timing discrepancy documented
- [ ] Containment (if any) authorized and documented
- [ ] Case disposition, owner, timestamps, rationale, next-review/closure approved
- [ ] Detection improvements captured: alert enrichment, registry cleanup visibility, safer test labeling

## References

- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/
