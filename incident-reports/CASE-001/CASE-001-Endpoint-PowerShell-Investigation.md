# CASE-001 — Endpoint Multistage PowerShell Investigation

**Project:** Mini Enterprise SOC — Wazuh / Windows Endpoint & Active Directory Detection<br>
**Case ID:** CASE-001<br>
**Case status:** Investigation completed for supplied telemetry; close-out checks pending (Run-key removal and clock synchronization).<br>
**Investigation type:** Controlled security simulation / lab detection validation<br>
**Detection:** `ENDPOINT_MULTISTAGE_POWERSHELL`<br>
**Wazuh rule:** `100410` (level 10)<br>
**Finding ID:** `fe92e604e9d2a74957559197`<br>
**Evidence date:** 2026-10-17<br>

## 1. Executive summary

A Windows 10 endpoint generated three correlated Sysmon events: PowerShell was launched with `-EncodedCommand` (event 1), the same process wrote a value to the user's `Run` registry key (event 13), and it established a TCP connection to the Wazuh Manager lab host (event 3). The events share the same Sysmon `ProcessGuid`, and all three occurred within approximately 2.30 seconds. The endpoint correlator created finding `fe92e604e9d2a74957559197`; the finding adapter forwarded it, Wazuh rule `100410` fired, and the Discover view showed `data.agent_name = WIN10-ENDPOINT01`.

**Analyst verdict:** **Benign true positive / authorized security simulation.** The detector correctly matched its target behavior. The activity was generated deliberately in the isolated lab and **does not establish compromise**, command-and-control activity, or data exfiltration. A severity-10 detection is a triage signal, not proof of a confirmed incident.

## 2. Asset and alert context

| Field | Value |
|---|---|
| Wazuh source agent ID | `001` |
| Wazuh source agent name | `WIN10-ENDPOINT01` |
| Windows hostname | `CRIE2910` |
| Windows user | `CRIE2910\vboxuser` |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Sysmon `ProcessGuid` | `{e4e2770f-6c4a-6ad3-2c01-000000002200}` |
| Destination | `192.168.56.10:18080/TCP` |
| Finding ID | `fe92e604e9d2a74957559197` |
| Wazuh alert rule/level | `100410` / `10` |

**Important field semantics:** Wazuh's outer `agent.name` can identify the local Wazuh Manager for alerts generated from the manager's adapter output file. The original affected endpoint is recorded in `data.agent_id` and `data.agent_name`.

## 3. Evidence and event timeline

Extracted source: Wazuh archive records filtered to agent `001`, channel `Microsoft-Windows-Sysmon/Operational`, and record IDs `104556`, `104596`, `104647`.

| Sysmon systemTime (UTC) | Event ID | Event Record ID | Action |
|---|---:|---:|---|
| 2026-10-17 12:38:35.1062737 | 1 | 104556 | Created child `powershell.exe` using `-NoProfile -NonInteractive -EncodedCommand` |
| 2026-10-17 12:38:36.2915070 | 13 | 104596 | Set user Run-key value `SOC-Lab-E2E-20261017193836` to `notepad.exe` |
| 2026-10-17 12:38:37.4028982 | 3 | 104647 | TCP connection `192.168.56.20:49873` -> `192.168.56.10:18080` |

Elapsed time from first to final event: **2.2966245 seconds**, within the endpoint detector's 120-second correlation window. All three source events reported the same `ProcessGuid`.

### Timestamp-quality observation

The following pairs were present in the supplied data:

| Event | Sysmon `systemTime` (UTC) | Wazuh archive `timestamp` (UTC) | Source ahead of archive |
|---|---|---|---:|
| 1 | 12:38:35.1062737 | 12:37:20.661 | 74.445 s |
| 13 | 12:38:36.2915070 | 12:37:22.226 | 74.066 s |
| 3 | 12:38:37.4028982 | 12:37:23.932 | 73.471 s |

This repeated ~74-second discrepancy suggests an outstanding clock or timestamp-provenance problem. **This report orders endpoint events by their original Sysmon `systemTime`; it does not assume Wazuh ingest timestamps represent the same clock.** Cross-host chronology must not be asserted until the discrepancy is investigated.

## 4. Technical findings

### 4.1 Encoded PowerShell execution — Sysmon ID 1

Observed executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, launched by another `powershell.exe` under `CRIE2910\vboxuser`. Its command line included `-EncodedCommand` with a Base64-encoded PowerShell script.

The known controlled simulation script creates an innocuous Run-key value, connects to the lab-only TCP listener, sends the short marker `SOC-LAB-E2E`, and attempts to remove the test registry value in a `finally` block. The full Base64 payload has **not been independently decoded and verified in this report**; that can be performed as a read-only evidence-enrichment step.

**ATT&CK:** `T1059.001` — PowerShell. The existence of `-EncodedCommand` is a useful investigative signal but is not itself proof of malicious execution.

### 4.2 User Run-key change — Sysmon ID 13

Target from Sysmon, normalized for readability:

`HKU\S-1-5-21-3866759802-943638242-2602647168-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC-Lab-E2E-20261017193836`

Registry value data: `C:\Windows\System32\notepad.exe`.

**ATT&CK:** `T1547.001` — Registry Run Keys / Startup Folder. The registry write is a persistence-related indicator, **not proof of lasting persistence**. The test script was designed to clean up after itself, but independent removal verification is still pending.

### 4.3 TCP connection — Sysmon ID 3

Same process: TCP from `192.168.56.20:49873` to `192.168.56.10:18080`. This IP and listener are owned by the isolated SOC lab. The test script was designed to send `SOC-LAB-E2E` to that listener. Sysmon ID 3 does not capture the application data payload and does not by itself prove exfiltration or C2.

### 4.4 Correlation reasoning

**Conditions met:** Sysmon events `1`, `13`, and `3` share the same agent and process GUID; event 1 contains encoded PowerShell execution; event 13 targets a Run key; event 3 contains a destination IP; all fell within the configured correlation window. The correlator did not require event 3 to precede event 13, which matches the observed chronological order.

## 5. Triage outcome and response decision

- **Detection outcome:** True positive for the behavioral detection conditions.
- **Security incident outcome:** No confirmed compromise. Activity was an **authorized, controlled lab simulation**.
- **Recommended operational disposition:** Close as authorized test *after* verifying test artifact cleanup and recording lab authorization; do not isolate the endpoint solely because this planned test fired rule `100410`.
- **If observed outside an approved test:** Validate the process tree, decode the PowerShell payload without executing it, inspect Run-key persistence, correlate related process/network/authentication events, identify the destination owner and assess whether escalation/isolation is warranted.

## 6. Outstanding verification steps

1. **Verify Run-key cleanup independently** on the original user hive; the existence of a cleanup command is not evidence that deletion succeeded.
2. **Check time synchronization** on both Windows 10 and the Ubuntu Wazuh Manager; document the source of the recurring ~74-second offset.
3. **Record chain of custody:** calculate SHA-256 of the source `sysmon-events.jsonl` evidence file; retain Wazuh Discover screenshot and, if possible, record the log extraction command/time.
4. **Optionally decode the original `-EncodedCommand` read-only** to attach reviewed script text or a brief summary as further evidence.

## 7. Evidence manifest (local files, not automatically included)

| Artifact | Description | Verification |
|---|---|---|
| `evidence/sysmon-events.jsonl` | Three raw Sysmon JSONL records | `wc -l` returned `3` |
| `evidence/sysmon-events.sha256` | SHA-256 manifest | Pending |
| Discover screenshot | Rule `100410`, source agent name, finding ID | Observed in user-provided screenshot |
| `/var/log/soclab-findings.jsonl` | Endpoint correlator output | Matching finding observed |
| `/var/log/soclab-alerts.jsonl` | Finding adapter output | Matching finding observed |
| `/var/ossec/logs/alerts/alerts.json` | Wazuh rule-100410 alert | Matching finding observed |

## 8. Reproducibility and limitations

This document is based on the command outputs and screenshots supplied by the lab operator, not a forensic disk image. The three event timestamps and record IDs are taken directly from their collected JSONL evidence. The registry-cleanup claim and actual wire payload are not independently verified by the three Sysmon events alone. This is a simulated scenario, not an observed third-party intrusion. Any public GitHub release should redact environment-specific secrets and review SID, usernames, hostname, and network information for disclosure suitability.

## 9. References

- MITRE ATT&CK — PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK — Registry Run Keys / Startup Folder: https://attack.mitre.org/techniques/T1547/001/
