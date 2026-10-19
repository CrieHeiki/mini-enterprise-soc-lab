# CASE-002 — Active Directory Domain Admins Membership Investigation

**Project:** Mini Enterprise SOC — Wazuh / Windows Endpoint & Active Directory Detection<br>
**Case ID:** CASE-002<br>
**Case status:** Technical analysis documented; administrative close-out and artifact verification pending<br>
**Investigation type:** Controlled AD security simulation / detection-validation case<br>
**Detection:** `AD_PRIVILEGE_ESCALATION`<br>
**Wazuh rule:** `100411` (level 12)<br>
**Finding ID:** `2e12ff986ddf9ba1bfb06375`<br>
**Source agent:** `002` / `DC01` / `192.168.56.30`<br>
**Observed Windows computer:** `WIN-I3LO9UQPOOR.corp.soc.test`<br>
**Evidence event date:** 2026-10-15 (source-event UTC; see clock discrepancy below)<br>

## 1. Executive summary

Windows Security event **4720** records creation of domain account `CORP\soc-ad-1014184656` by `CORP\Administrator`. **8.582 seconds** later, event **4728** records the same account being added to the privileged **Domain Admins** group. The events share the newly created account's SID, the domain controller, the administrative subject and its logon ID (`0x120A62`). The live AD correlation engine generated finding `2e12ff986ddf9ba1bfb06375`; the adapter forwarded it and Wazuh rule `100411` generated the aggregate alert.

An additional, separately identified event **4729** shows that this **same account was removed from Domain Admins about 5.040 seconds after being added**. The event was not one of the two required inputs to the original correlator, but is material to the investigation and prevents an incomplete conclusion that privileged membership remained in place.

**Analyst verdict:** **Authorized security simulation / detection validated**, assuming the observed changes were part of the operator's approved lab test as described. The three Security events demonstrate an account creation and temporary privileged group membership, but **do not demonstrate unauthorized access, successful use of the new account, or persistence of the group membership**. The operator reported subsequent AD checks matched the expected result, but their full text output was not supplied for inclusion in the evidence package.

## 2. Scope, context, and alert metadata

| Field | Value |
|---|---|
| Domain | `corp.soc.test` / `CORP` |
| Wazuh source agent | `DC01` / `002` |
| Observed Windows computer | `WIN-I3LO9UQPOOR.corp.soc.test` |
| Created account | `soc-ad-1014184656` |
| Account SID | `S-1-5-21-2564887276-2185444859-3392565797-1108` |
| Group | `Domain Admins` |
| Group SID | `S-1-5-21-2564887276-2185444859-3392565797-512` (RID 512) |
| Subject / initiating account | `CORP\Administrator` |
| Subject SID | `S-1-5-21-2564887276-2185444859-3392565797-500` |
| Subject logon ID | `0x120A62` |
| Correlation interval | `8.582` seconds, within configured 300-second window |
| Wazuh rule / level | `100411` / `12` |
| Adapter `integration_test` | `false` for this finding (indicates not flagged as adapter replay; **not** proof of a real attack) |

The Wazuh alert's outer `agent` is sometimes `000` / `WAZUH-SIEM`, because custom correlation output was ingested locally by the manager. The **originating** domain controller is carried in `data.agent_id = 002` and `data.agent_name = DC01`.

## 3. Evidence sources and chain of events

### 3.1 Evidence discovery

The first attempt to extract records `5306` and `5309` from `ossec-archive-15.json` yielded zero rows. A broader search identified the matching records in:

`/var/ossec/logs/archives/2026/Oct/ossec-archive-14.json`

Record IDs **5306 (4720)**, **5309 (4728)**, and **5312 (4729)** were matched with Agent `002`, Windows channel `Security`, and the account and group SIDs. The operator separately queried the DC01 Windows Security log via `Get-WinEvent` and showed the corresponding `4720` and `4728` records.

**Proposed local evidence export** (on the Ubuntu manager): `evidence/ad-events.jsonl`, holding three raw JSON records. The archive discovery and the 4720/4728 Windows Event Viewer contents are visible in the supplied command output, but the created `ad-events.jsonl` file itself has not been uploaded to this report-generating environment. No original evidence or SHA-256 digest is fabricated or attached here.

### 3.2 Event timeline

The rows below use Windows Security `systemTime` (UTC) to order same-source events. Archive reception timestamps are **not** used to infer cross-host causality until the clock issue is resolved.

| Windows event time (UTC) | Event ID | Record ID | Actor | Observation |
|---|---:|---:|---|---|
| 2026-10-15 01:46:56.7984244 | **4720** | **5306** | `CORP\Administrator` | Created domain account `soc-ad-1014184656` |
| 2026-10-15 01:47:05.3802156 | **4728** | **5309** | `CORP\Administrator` | Added that account to `CORP\Domain Admins` |
| 2026-10-15 01:47:10.4203101 | **4729** | **5312** | `CORP\Administrator` | Removed the same account from `CORP\Domain Admins` |

Time from account creation to group addition: **8.5817912 seconds** (rounded by the correlator to `8.582`).<br>
Time from group addition to removal: **5.0400945 seconds**.<br>
Total span of three events: **13.6218857 seconds**.

**ATT&CK context:** Creating a domain account maps to `T1136.002` (Domain Account). Adding an account to a privileged domain group aligns more specifically with `T1098.007` (Additional Local or Domain Groups); the deployed aggregate rule uses parent technique `T1098` (Account Manipulation). These are behavioral classifications, not evidence of adversarial intent.

## 4. Analysis of individual Security events

### 4.1 Event ID 4720 — Domain account created

- New account name: `CORP\soc-ad-1014184656`.
- New account SID: `S-1-5-21-2564887276-2185444859-3392565797-1108`.
- Subject: `CORP\Administrator`; subject SID ends in `-500`.
- Subject Logon ID: `0x120A62`.
- `Password Last Set: <never>` in the original Security event message.
- `User Account Control` in the event message includes **Account Disabled** and **Normal Account**.

At **creation time**, the user was recorded as disabled with no password last-set time. This does not prove the account remained disabled at later times or that no additional account-management events occurred.

### 4.2 Event ID 4728 — Member added to security-enabled global group

- Member SID: `S-1-5-21-2564887276-2185444859-3392565797-1108` — identical to the new-account SID in 4720.
- Member distinguished name: `CN=soc-ad-1014184656,CN=Users,DC=corp,DC=soc,DC=test`.
- Group name: `Domain Admins` / group domain: `CORP`.
- Target group SID: `S-1-5-21-2564887276-2185444859-3392565797-512` — Domain Admins RID 512.
- Subject: `CORP\Administrator`; subject Logon ID: `0x120A62`.

The SID match removes the ambiguity that the new account and the newly privileged member might be unrelated users with different names. This was a high-risk group-membership change that warrants triage even in a lab.

### 4.3 Event ID 4729 — Member removed from security-enabled global group

- Member SID: **same** SID ending `-1108`.
- Group SID: **same** SID ending `-512`.
- Subject: `CORP\Administrator` with same observed Logon ID.
- Removal happened **about five seconds after addition**.

This independently captured event explains the short duration of the group membership in the test. **It proves removal was logged at that time, but not that the member was never re-added later**; the current group-membership check and intervening logs are needed for that stronger claim.

### 4.4 Correlation chain and alert validation

The live detector correlates 4720 and 4728 by source domain controller, SID equality and a **300-second** event-time window. Both events were associated with Agent `002`, and the correlated finding retained the operator and group identifiers. The adapter output contained `source_monitor: soclab-ad-findings.jsonl`, `evidence_event_ids: "4720,4728"`, `evidence_record_ids: "5306,5309"`, `integration_test: false`, and the expected account metadata.

The Wazuh archived aggregate alert had `rule.id: 100411` and corresponding `data.finding_id`. Separate built-in/custom Wazuh alerts also appeared for initial creation (`100220`, level 7) and Domain Admins membership change (`60159`, level 12). **Event 4729 was found through the expanded investigation**, not by the original two-event correlation rule.

## 5. Clock integrity and timestamp limitations

A historical discrepancy is present between DC01 source-event times and Wazuh archive timestamps:

| Event | DC01 `systemTime` UTC | Wazuh archive `timestamp` UTC | DC01 timestamp ahead by |
|---|---|---|---:|
| 4720 | 2026-10-15 01:46:56.798 | 2026-10-14 12:53:57.757 | 12 h 52 m 59.041 s |
| 4728 | 2026-10-15 01:47:05.380 | 2026-10-14 12:54:06.369 | 12 h 52 m 59.011 s |
| 4729 | 2026-10-15 01:47:10.420 | 2026-10-14 12:54:11.381 | 12 h 52 m 59.039 s |

The source events are in UTC (`Z`), so the discrepancy is **not explained simply by DC01 displaying UTC−07:00 while Ubuntu displays UTC+07:00**. This is a significant historical clock or timestamp-provenance issue whose specific cause is not established. It affected archive-day selection: the matching events were archived in the October 14 file.

**Current-state follow-up (2026-10-18):** the operator showed DC01's `w32tm /query /source` as `time.windows.com,0x8`, `Leap Indicator: 0`, `Stratum: 5`, and recent successful synchronization; the Ubuntu Wazuh manager reported NTP active and system clock synchronized. DC01 `2026-10-18T06:18:24.4357568-07:00` converts to `13:18:24.436 UTC`, nearly matching Ubuntu `13:18:25 UTC` when checked. This confirms acceptable time agreement **at the later observation**, not for the historical events, and does not retrospectively alter logged timestamps.

## 6. Risk and disposition

**Potential impact if unauthorized:** a newly created domain account added to Domain Admins is a critical identity-and-access concern, even if the grant is brief. An analyst should investigate who authorized it, how the initiating Administrator session was established, and whether any privileged logons or actions occurred while group membership was active.

**Evidence-supported limits:** the original 4720 record indicates a disabled new account at creation; 4729 shows membership removal; neither these three events nor the correlated alert alone establish successful login, permission use, lateral movement, data access, or account compromise. A `Severity=High` finding is an operational priority, not an automatic incident verdict.

**Working classification:** **Behavioral true positive; authorized lab simulation** based on the operator's test context. The case can be marked as *validated detection*, but incident close-out should cite the approved test context and record actual membership/cleanup verification. `integration_test = false` means only that this adapter entry was not flagged as a replay test; it does not change the simulation classification.

## 7. Response guidance / follow-up checks

1. Preserve the three raw source events (4720/4728/4729) and corresponding Wazuh correlation alert; compute and verify the export SHA-256 digest.
2. Validate the operator's reported AD state against saved read-only command output: `Get-ADUser` for presence/Enabled and `Get-ADGroupMember -Identity "Domain Admins"` for current direct membership.
3. Document operator authorization for this lab change and the planned rollback/removal; confirm whether the created test account remains and, if so, whether it should be disabled or deleted during lab cleanup (change only after approval and evidence preservation).
4. Where greater assurance is needed, review related account modifications (4722, 4725, 4738), additional group changes (4728/4729) and authentication evidence (e.g. relevant 4624/4768/4769 records). **No outcome of those checks is asserted in this report.**
5. Troubleshoot or document the historical DC01/Wazuh time offset for future cross-host incident timelines. Do not edit the original log timestamps.
6. Improve metadata for Wazuh custom rule `100220` if it targets domain account creation: `T1136.002` is more appropriate than its observed `T1136.001` (Local Account) for this particular domain scenario.

## 8. Evidence inventory

| Item | Source | Status |
|---|---|---|
| 4720 / Record 5306 | `/var/ossec/logs/archives/2026/Oct/ossec-archive-14.json` | Located and details reviewed from operator's output |
| 4728 / Record 5309 | Same archive | Located; additionally verified through `Get-WinEvent` on DC01 |
| 4729 / Record 5312 | Same archive | Located; SID and group matched |
| Live correlation finding | `/var/log/soclab-ad-findings.jsonl` | Matching finding reviewed |
| Adapter forwarded finding | `/var/log/soclab-alerts.jsonl` | Matching record reviewed; `integration_test: false` |
| Wazuh alert 100411 | Wazuh archive and Discover | Matching Wazuh archive alert reviewed |
| `evidence/ad-events.jsonl` | Local CASE-002 directory on user's Ubuntu VM | Export command supplied; content not uploaded here |
| `evidence/ad-events.sha256` | User's Ubuntu VM | Digest verification output not supplied here |
| Current AD membership state | `Get-ADUser`, `Get-ADGroupMember` on DC01 | Operator reported expected results; output not attached |
| Clock follow-up | DC01 `w32tm`, Ubuntu `timedatectl` | Output reviewed; clocks presently agree |

### Recommended export command on Ubuntu Wazuh Manager

```bash
cd ~/SOC-Lab/incident-reports/CASE-002
mkdir -p evidence
sudo jq -R -c '
  fromjson?
  | select(
      .agent.id == "002"
      and .data.win.system.channel == "Security"
      and (
        ((.data.win.system.eventID | tostring) == "4720" and (.data.win.system.eventRecordID | tostring) == "5306")
        or ((.data.win.system.eventID | tostring) == "4728" and (.data.win.system.eventRecordID | tostring) == "5309")
        or ((.data.win.system.eventID | tostring) == "4729" and (.data.win.system.eventRecordID | tostring) == "5312")
      )
  )
' /var/ossec/logs/archives/2026/Oct/ossec-archive-14.json > evidence/ad-events.jsonl

wc -l evidence/ad-events.jsonl   # expected: 3
sha256sum evidence/ad-events.jsonl > evidence/ad-events.sha256
sha256sum -c evidence/ad-events.sha256
```

Keep the evidence export in the restricted lab repository or a private evidence store until names/SIDs/host details have been reviewed for public disclosure.

## 9. Opportunities for better SOC detection and response

- Enrich the current 4720→4728 correlated finding with a **4729 membership-removal follow-up status**, without assuming that a removal makes the earlier escalation irrelevant.
- Track additional group changes after 4729, to detect re-addition, and add analyst fields for `authorization_status`, `case_disposition`, and `cleanup_verified` separate from the adapter's `integration_test` field.
- Validate end-to-end ingestion and time alignment on newly generated, authorized benign AD events only after the clock issue is resolved; no need to create another privileged account to close this case.
- For demonstration on GitHub, include a sanitized alert screenshot, correlation logic, an explicit test/simulation disclaimer, and incident response decisions rather than just detection counts.

## 10. References

- MITRE ATT&CK, Domain Account (`T1136.002`): https://attack.mitre.org/techniques/T1136/002/
- MITRE ATT&CK, Account Manipulation (`T1098`): https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK, Additional Local or Domain Groups (`T1098.007`): https://attack.mitre.org/techniques/T1098/007/
