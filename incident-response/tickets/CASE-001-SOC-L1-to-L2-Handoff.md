# SOC-L1 → SOC-L2 Handoff — CASE-001 (Tabletop Exercise)

**Document status:** DRAFT / TABLETOP ONLY — NOT A REAL ESCALATION OR INCIDENT NOTIFICATION<br>
**Based on:** Observed SOC-Lab events, Windows 10 endpoint simulation on 2026-10-17<br>
**Exercise decision point:** Assume authorization evidence is **temporarily unavailable when the alert arrives**. This assumption is hypothetical. The underlying historical event was a **known, controlled lab simulation**.

## 1. Ticket metadata

| Field | Entry |
|---|---|
| Ticket / case ID | `SOC-TABLETOP-001` / `CASE-001` |
| Rule ID / level | `100410` / `10` (Wazuh detection level; not proof of compromise) |
| Detection | `ENDPOINT_MULTISTAGE_POWERSHELL` |
| Finding ID | `fe92e604e9d2a74957559197` |
| Source endpoint | Wazuh agent `001`, `WIN10-ENDPOINT01`; Windows computer `CRIE2910` |
| Reported alert timestamp | `2026-10-17 12:37:27.019 UTC` (Wazuh alert time; historical clock mismatch applies) |
| Earliest Sysmon source event | `2026-10-17 12:38:35.106 UTC` (Windows systemTime) |
| Reporter / reviewer | SOC L1 (lab operator); name and completion time: **to be recorded** |
| Scope | Isolated SOC lab, not production |
| Exercise priority | High **if** unapproved/unknown authorization; controlled-test handling in actual lab |
| Authorization reference | Hypothetical exercise: `NOT CONFIRMED`; real lab context: user-initiated test, formal change ID not provided |
| Handoff status | `DRAFT — NOT SENT`; L2 acknowledgment/approval: not performed |

## 2. Confirmed observations from supplied evidence

| Source-time UTC | Event / record | Direct observation |
|---|---|---|
| `12:38:35.106` | Sysmon ID 1 / `104556` | `CRIE2910\\vboxuser` launched `powershell.exe -NoProfile -NonInteractive -EncodedCommand ...`; parent `powershell.exe` |
| `12:38:36.292` | Sysmon ID 13 / `104596` | Same process GUID wrote `HKCU\\...\\Run\\SOC-Lab-E2E-20261017193836`; value `C:\\Windows\\System32\\notepad.exe` |
| `12:38:37.403` | Sysmon ID 3 / `104647` | Same process connected `192.168.56.20:49873` → `192.168.56.10:18080/TCP` |

- **Correlation key:** `{e4e2770f-6c4a-6ad3-2c01-000000002200}` (same ProcessGuid on events 1/13/3).
- **Finding pipeline:** Correlator → Finding Adapter → Wazuh Rule `100410`; `data.agent_id=001`, `data.agent_name=WIN10-ENDPOINT01`.
- **Test context:** The lab operator intentionally initiated the encoded PowerShell and local TCP-listener simulation. `data.integration_test=false` means the finding was not adapter-replay tagged; it does **not** mean a real intrusion.
- **MITRE mapping:** T1059.001 (PowerShell execution); T1547.001 (Run key modification indicator).

## 3. Analyst assessment

**Behavioral detection:** Matched / true positive for the detection rule.<br>
**Compromise:** Not established.<br>
**Network activity:** Internal lab destination; Sysmon ID 3 does not establish exfiltration or C2.<br>
**Persistence:** Run-key write observed; lasting persistence not established.<br>
**Outstanding check:** Validate current state of Run value `SOC-Lab-E2E-20261017193836` in the **original** `CRIE2910\\vboxuser` registry hive, and attach the actual command output.

**Historical clock limitation:** Windows Sysmon `systemTime` is about **74 seconds later** than Wazuh archive timestamps for the same events; preserve both timestamps and do not silently adjust the raw logs.

## 4. Actions / evidentiary status

| Action | Status |
|---|---|
| Initial Wazuh alert and agent identity | **Previously verified by operator** |
| All 3 Sysmon raw evidence records | **Verified** |
| `evidence/sysmon-events.sha256` | **Verified — `OK` reported** |
| Confirm current Run-key absence in correct user hive | **PENDING — actual output not provided** |
| Formal authorization reference | **NOT RECORDED** (lab intent known) |
| Real L2 escalation / acknowledgment | **NOT PERFORMED** — tabletop only |
| Endpoint isolation / deletion / credential change | **NOT PERFORMED**, and not authorized by this draft |

## 5. Exercise handoff to SOC L2 (hypothetical unknown-authorization branch)

**Reason for hypothetical escalation:** If an otherwise identical multi-stage PowerShell / Run-key / TCP alert were received without a confirmed change/test record, Tier 1 should escalate for timely validation rather than label the event benign on technical pattern alone.

**Questions / decisions requested:**

1. Confirm authorization owner, approved time window, operator, and expected destination.
2. Review encoded command **offline**, inspect extended process/network/Defender evidence, and confirm whether any suspicious activity occurred beyond the test pattern.
3. Confirm current Run-key status in the correct user context and any other persistence indicators.
4. Assess whether containment is necessary **only if** unexpected or harmful activity is corroborated; any isolation, process termination, registry deletion or firewall change requires approved responder action.

**No actual L2 escalation occurred in this lab exercise.** This is a mock request, not a claim of operational incident response.

## 6. Evidence locations (on operator's Ubuntu VM)

| Reference | Description |
|---|---|
| `~/SOC-Lab/incident-reports/CASE-001/evidence/sysmon-events.jsonl` | 3 original Sysmon events exported from Wazuh archives |
| `~/SOC-Lab/incident-reports/CASE-001/evidence/sysmon-events.sha256` | Integrity manifest (operator reported successful verification) |
| `~/SOC-Lab/incident-reports/CASE-001/CASE-001-Endpoint-PowerShell-Investigation.md` | Case report; pending checks must be updated when verified |
| Wazuh Discover: `rule.id: "100410"` | Alert and original source metadata; select time range covering 2026-10-17 |

**No raw evidence is embedded in this markdown.** Keep potentially sensitive raw logs private; publish sanitized summaries for GitHub.

## 7. Expected disposition and closure gates

- **Actual lab fact:** Authorized, controlled simulation. Behavioral true positive, *not* confirmed compromise.
- **Proposed disposition:** `Authorized Security Simulation — Pending L1 documentation/closure review` until the current Registry check and approval record are documented.
- **Mock escalation branch:** `Awaiting L2 authorization review` (exercise only; not a real ticket state).
- **Close after:** attach Registry verification, retain evidence integrity result, document observed clock skew and test ownership/authorization, record simulated reviewer decision.

**SOC L2 recipient / sign-off:** `NOT APPLICABLE — TABLETOP`<br>
**End-of-exercise review:** `PENDING`
