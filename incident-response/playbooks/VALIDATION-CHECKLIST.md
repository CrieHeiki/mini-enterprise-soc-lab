# Phase 5.8 — Read-only Incident Response Playbook Validation

**Aim:** Demonstrate that a SOC Tier 1 analyst can follow both response playbooks using **existing** case evidence. No new encoded PowerShell, privileged account creation, or Active Directory membership changes are necessary.

## Preconditions

- Wazuh Dashboard reachable and `wazuh-alerts-*` accessible.
- CASE-001 raw evidence `~/SOC-Lab/incident-reports/CASE-001/evidence/sysmon-events.jsonl` exists (expected 3 lines).
- CASE-002 raw evidence `~/SOC-Lab/incident-reports/CASE-002/evidence/ad-events.jsonl` exists (expected 3 lines, including ID 4729).
- Cases/reports/queries use known finding IDs; source identity is in `data.agent_*`, not manager-local `agent.*`.
- Original evidence hashes should be calculated **once at acquisition** and checked before analysis; don't normalize or modify original logs and overwrite manifests.

## Test V-01 — Endpoint investigation

- [ ] Discover filter `rule.id: "100410"` shows finding `fe92e604e9d2a74957559197`.
- [ ] Record source endpoint `data.agent_id=001`, `data.agent_name=WIN10-ENDPOINT01`.
- [ ] `wc -l .../CASE-001/evidence/sysmon-events.jsonl` returns 3.
- [ ] Sysmon events 1,13,3 share one ProcessGuid; check timestamps ordered using `systemTime`.
- [ ] Explain why encoded command + Run key + TCP **matches the rule but does not prove a compromise**.
- [ ] Read-only check for temporary Run value on `CRIE2910\vboxuser` hive completed; attach real output.
- [ ] Document historical ~74 s timestamp discrepancy.
- [ ] Choose disposition **Authorized Security Simulation** only if approval/test context verified; otherwise escalate.

## Test V-02 — AD investigation

- [ ] Discover filter `rule.id: "100411"` shows finding `2e12ff986ddf9ba1bfb06375`.
- [ ] Original DC agent `002/DC01`; don't mistake manager-local adapter agent `000` for target.
- [ ] `wc -l .../CASE-002/evidence/ad-events.jsonl` returns 3.
- [ ] Security events 4720/4728/4729 have Record IDs 5306/5309/5312.
- [ ] 4720 new-account SID = 4728 member SID = 4729 member SID.
- [ ] 4728 and 4729 target the same group SID ending `-512`.
- [ ] Account creation→addition = 8.582 s; addition→removal = 5.040 s.
- [ ] DC01 account existence, Enabled state and current Domain Admins membership checked read-only; attach actual output.
- [ ] Document old DC01/Wazuh ~12 h 53 m discrepancy; current NTP status is not retroactive evidence.
- [ ] Explain why Event 4729 is *follow-up evidence* (the detector triggers on 4720+4728).
- [ ] Determine authorized test vs unknown privilege grant; escalate promptly if authorization is unclear.

## Test V-03 — SOC L1 → L2 desk exercise

Use `HANDOFF-TEMPLATE.md` to write **one mock handoff** without executing any containment action:

- [ ] Include finding/rule IDs, severity, user/asset identity, chronological events and original evidence locations.
- [ ] Clearly separate confirmed facts from assumptions, label the case as controlled lab simulation.
- [ ] Include risks and explicitly state which action needs L2/IR approval.
- [ ] Include UTC/timestamp-source mismatch as a limitation.
- [ ] Name requested decision: review authorization and approve/no-op appropriate to the case.

## Acceptance criteria

**Pass:** both cases have verifiable raw-event trails, correct correlation explanations, realistic authorization/escalation decisions, saved analyst evidence/checksums, and an understandable L1→L2 handoff.<br>
**Pending:** indicate each unmet checkbox rather than declaring Phase 5.8 complete.<br>
**No production claims:** this is a lab tabletop/exercise, not a real-world compromise or live containment exercise.
