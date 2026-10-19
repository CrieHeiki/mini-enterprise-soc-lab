# IR-002 — New AD Account Added to Domain Admins

**Project:** Mini Enterprise SOC — Wazuh / Windows Endpoint & Active Directory Detection<br>
**Document version:** 1.0 | **Status:** Lab playbook (not a production change authorization)<br>
**Owner / primary handler:** SOC Tier 1 | **Containment approver:** SOC L2 / Incident Commander / AD administrator<br>
**Trigger:** `AD_PRIVILEGE_ESCALATION`, Wazuh rule `100411` (level 12)<br>
**Validated lab case:** [CASE-002](../../incident-reports/CASE-002/CASE-002-AD-Privilege-Escalation-Investigation.md) — finding `2e12ff986ddf9ba1bfb06375`<br>
**Reference:** NIST SP 800-61 Rev. 3; MITRE ATT&CK T1136.002 / T1098.007.

> **Purpose:** Investigate rapid creation of a domain account and subsequent addition to a privileged group. Because Domain Admins membership is high impact, prioritize verification of **authorization**, **identity/SID relationship**, **privileged session context**, **follow-on activity**, and **whether membership persists**. **Do not automatically treat short-lived access or `integration_test=false` as either safe or malicious.**

## 0. Initial action and authority boundaries

1. Create ticket, preserve Wazuh alert, and notify SOC L2/AD owner **promptly** when the change is unknown or unapproved. Domain Admins membership is a potentially critical finding even if the user account was short-lived.
2. SOC L1 may query Wazuh and DC01 logs, verify current AD attributes/membership **read-only**, save/hashes, document, and escalate.
3. **Do not** disable/delete users, remove Domain Admins members, reset Administrator credentials, change GPO, reboot DC01 or isolate a domain controller without an authorized IR/change decision. Such actions can disrupt production authentication and destroy leads.
4. Check whether a documented lab test created the account; confirm test operator, change window and cleanup intention.

## 1. Alert validation

In Wazuh Discover select `wazuh-alerts-*`, DQL `rule.id: "100411"`, date range covering the original alert. Display `data.finding_id`, `data.agent_id`, `data.agent_name`, `data.account_name`, `data.account_sid`, `data.group_name`, `data.group_sid`, `data.created_by`, `data.added_by`, `data.evidence_record_ids`, `data.integration_test`.

For the known controlled CASE-002:

| Field | Value |
|---|---|
| Finding ID | `2e12ff986ddf9ba1bfb06375` |
| Agent ID / name | `002` / `DC01` |
| Windows event host | `WIN-I3LO9UQPOOR.corp.soc.test` |
| Account | `CORP\soc-ad-1014184656` |
| User SID | `S-1-5-21-2564887276-2185444859-3392565797-1108` |
| Group | `CORP\Domain Admins` |
| Group SID | `S-1-5-21-2564887276-2185444859-3392565797-512` |
| Actor | `CORP\Administrator` |
| Rule level | `12` |
| Adapter `integration_test` | `false` (not replay; still a lab simulation) |

Manager-local adapter events may have **outer** `agent.id=000`; the actual source is in `data.agent_id=002` / `data.agent_name=DC01`.

## 2. Preserve evidence from Wazuh and DC01

The original records are in **October 14 Wazuh archive** despite Windows source-event `systemTime` indicating October 15 UTC. Use the confirmed archive path, not the date inferred solely from source timestamps.

```bash
umask 077
cd ~/SOC-Lab/incident-reports/CASE-002
mkdir -p evidence
sudo jq -R -c '
  fromjson?
  | select(.agent.id == "002"
    and .data.win.system.channel == "Security"
    and (
      ((.data.win.system.eventID|tostring)=="4720" and (.data.win.system.eventRecordID|tostring)=="5306")
      or ((.data.win.system.eventID|tostring)=="4728" and (.data.win.system.eventRecordID|tostring)=="5309")
      or ((.data.win.system.eventID|tostring)=="4729" and (.data.win.system.eventRecordID|tostring)=="5312")
    )
  )
' /var/ossec/logs/archives/2026/Oct/ossec-archive-14.json > evidence/ad-events.jsonl

wc -l evidence/ad-events.jsonl  # expected: 3
sha256sum evidence/ad-events.jsonl > evidence/ad-events.sha256
sha256sum -c evidence/ad-events.sha256
```

Do not recompute the hash later on an edited file and represent it as the original. Preserve raw records separately from analytic summaries. If archives moved or compressed, locate the actual path first instead of fabricating evidence.

Read-only cross-check on DC01 (PowerShell Administrator):

```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventRecordID=5306 or EventRecordID=5309 or EventRecordID=5312)]]' |
    Sort-Object RecordId |
    Select-Object TimeCreated, Id, RecordId, MachineName, Message |
    Format-List
```

## 3. Correlation and event timeline

| Windows `systemTime` UTC | ID / record | Interpretation |
|---|---|---|
| 2026-10-15 01:46:56.798 | 4720 / 5306 | Administrator created `soc-ad-1014184656` |
| 2026-10-15 01:47:05.380 | 4728 / 5309 | Same SID added to Domain Admins (+8.582 s) |
| 2026-10-15 01:47:10.420 | 4729 / 5312 | Same SID removed from same group (+5.040 s) |

4720: `targetSid` **must match** 4728/4729: `memberSid`. 4728/4729 `targetSid` **must match** the Domain Admins group SID ending `-512`. Check source host and the actor's `subjectUserSid`, `subjectUserName`, `subjectLogonId`, not just account display names.

Verification using the preserved JSONL:

```bash
jq -s '
  (map(select((.data.win.system.eventID|tostring)=="4720"))|first) as $c |
  (map(select((.data.win.system.eventID|tostring)=="4728"))|first) as $a |
  (map(select((.data.win.system.eventID|tostring)=="4729"))|first) as $r |
  {
    same_created_and_added: ($c.data.win.eventdata.targetSid==$a.data.win.eventdata.memberSid),
    same_added_and_removed: ($a.data.win.eventdata.memberSid==$r.data.win.eventdata.memberSid),
    same_group: ($a.data.win.eventdata.targetSid==$r.data.win.eventdata.targetSid),
    domain_admins: (($a.data.win.eventdata.targetUserName=="Domain Admins") and ($a.data.win.eventdata.targetSid|endswith("-512"))),
    actor_created: $c.data.win.eventdata.subjectUserName,
    actor_added: $a.data.win.eventdata.subjectUserName,
    actor_removed: $r.data.win.eventdata.subjectUserName
  }
' evidence/ad-events.jsonl
```

All four booleans should be `true` in the validated lab case. **Event 4729 is a follow-up investigation observation, not part of the current 4720→4728 detector's trigger.** Its presence does *not* prove the account was never re-added after that point.

## 4. Verify current domain state (read-only)

On DC01, in Windows PowerShell with Active Directory module available:

```powershell
Get-ADUser -Filter "SamAccountName -eq 'soc-ad-1014184656'" -Properties Enabled,PasswordLastSet,MemberOf |
    Select-Object Name,SamAccountName,Enabled,PasswordLastSet,MemberOf

Get-ADGroupMember -Identity 'Domain Admins' |
    Where-Object { $_.SamAccountName -eq 'soc-ad-1014184656' } |
    Select-Object Name,SamAccountName,DistinguishedName
```

No output from `Get-ADGroupMember` means the account is **not a direct member at the time of the query**; it does not independently prove no historical privileged action. Check whether the account exists, is enabled, and has other privileged group memberships. Also determine whether there was later re-addition or membership via nested groups when appropriate.

**Additional investigation:** With an approved time range and the correct clock basis, inspect Security events `4722`, `4725`, `4738`, `4728`, `4729`, relevant authentication `4624`, `4768`, `4769` and actor `subjectLogonId=0x120a62`. If the investigation expands, involve AD administrators for validation of sessions, effective group memberships and DC replication context.

## 5. Severity and decision table

| Scenario | Analyst decision |
|---|---|
| Authorized test; 4720→4728→4729 verified; current membership absent; operator approved | **Behavioral true positive / authorized security simulation**; retain evidence and close only after review |
| Test authorization unknown / unexpected privileged grant | **Immediate SOC L2 + AD owner escalation** (High/Critical according to organizational impact) |
| Account is still directly/indirectly privileged or observed re-added | **Urgent L2/IR escalation**; prepare approved containment plan |
| Suspected compromise of built-in Administrator or suspicious successful logons | Treat as high-impact identity incident; urgent IR lead/AD team involvement |
| Missing 4729 or unclear state | Do not assume revocation; explicitly mark membership status **unverified** |

A short-lived group membership may still permit significant actions. The lab 4720 showed the created account **disabled at creation**, with `Password Last Set: <never>`, but that is **point-in-time evidence**, not proof it remained disabled or never authenticated.

## 6. Approved containment, eradication and recovery (L2/IR + AD owner)

After identifying business impact and preserving evidence, approved responders may consider: removing unauthorized group membership; disabling a malicious account; revoking sessions/tickets where feasible; resetting exposed privileged credentials; inspecting actions performed by affected accounts; restoring authorized permissions; and monitoring for re-addition. Actions should be sequenced with the domain owner, incident commander and change controls. Never casually isolate or restart DC01 or reset the built-in Administrator account as an automatic L1 response.

**For this lab:** The 4729 record suggests the membership was removed ~5 seconds after creation. Verify **current** AD state before any manual cleanup; do not recreate the privileged grant for playbook demonstration.

## 7. Historical clock discrepancy and evidentiary limitations

Windows DC01 `systemTime` for 4720 was **2026-10-15 01:46:56 UTC**, while Wazuh archived the same record at **2026-10-14 12:53:57 UTC**: DC01 time was ahead by **~12 h 53 m** in the historical records. Ubuntu/Wazuh and DC01 later reported successful NTP synchronization on 2026-10-18, but this does **not** retroactively correct previous events. Log source clock/timezone, preserve originals, and do not derive cross-host temporal order until clock accuracy is established.

## 8. L1→L2 handoff and closure checklist

Use [HANDOFF-TEMPLATE.md](HANDOFF-TEMPLATE.md) with: alert/finding/rule, account/group SID, actors, Security Record IDs, date-source discrepancies, current account state, evidence and hash, confirmed vs unconfirmed impacts, authorization status and requested response.

- [ ] Rule `100411`, original agent `002` and finding ID validated
- [ ] Events `4720`/`4728`/`4729` matched on user SID and group SID
- [ ] Current account Enabled/status and Domain Admins direct membership verified
- [ ] Test authorization or business approval documented
- [ ] Authentication and follow-on admin activity reviewed **if incident is not clearly authorized**
- [ ] Original evidence preserved + SHA-256 verified
- [ ] Historical clock discrepancy documented; all dates labeled with source/timezone
- [ ] Any account/privilege remediation explicitly approved, executed and verified by proper owner
- [ ] Case disposition and any remaining investigative gaps recorded
- [ ] Improvement noted: follow-up removal (4729), re-add events, and correct domain-account ATT&CK mapping

## References

- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK T1136.002: https://attack.mitre.org/techniques/T1136/002/
- MITRE ATT&CK T1098.007: https://attack.mitre.org/techniques/T1098/007/
