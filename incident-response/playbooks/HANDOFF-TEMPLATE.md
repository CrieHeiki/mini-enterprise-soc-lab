# SOC Tier 1 → SOC Tier 2 Incident Handoff Template

> Copy this template for each escalation; redact credentials and sensitive payloads before sharing. Do not claim tests or checks were completed without corresponding evidence.

## Ticket metadata

| Field | Entry |
|---|---|
| Ticket / case ID | `<CASE-ID>` |
| Alert rule / detection | `<RULE-ID> / <DETECTION>` |
| Finding ID | `<FINDING-ID>` |
| Reported time, timezone and source | `<YYYY-MM-DD HH:mm:ss TZ / Wazuh or Windows>` |
| Analyst and handoff time | `<NAME / UTC>` |
| Affected agent / hostname | `<data.agent_id / data.agent_name / actual hostname>` |
| Incident scope | `<LAB / PRODUCTION / UNKNOWN>` |
| Priority | `<P1/P2/P3 or org-specific>` |
| Authorization/test change ID | `<ID / NOT CONFIRMED>` |

## Observation / known facts

- **Trigger:**
- **Timeline (timezone and clock source for each row):**
- **Correlated event IDs and record IDs:**
- **Identity, process, destination, SID or group data:**
- **What raw evidence directly proves:**

## Assessment / unknowns

- **Suspected behavior:**
- **Impacted assets/accounts:**
- **Evidence against benign testing or in favor of expected activity:**
- **What is *not* proven (avoid speculation):**
- **Clock / telemetry gaps:**

## Actions already performed by SOC L1 (read-only)

- [ ] Reviewed Wazuh Discover
- [ ] Validated underlying Windows/Sysmon event records
- [ ] Preserved evidence files and verified SHA-256
- [ ] Checked current endpoint/AD state read-only
- [ ] Checked test authorization/change window

## Requested SOC L2/IR decision

- **Reason for escalation:**
- **Requested next action (e.g., validate authorization, expand scope, approve containment):**
- **Potential business impact / DC dependencies:**
- **Named approver and decision (when available):**

## Evidence references

| Path / dashboard link | Description | SHA-256 / access classification |
|---|---|---|
| | | |

## Disposition / sign-off

- **L2 recipient:**
- **Acknowledged at (UTC):**
- **Decision:**
- **Approval references:**
- **Owner of next action:**
- **Next review / closure conditions:**
