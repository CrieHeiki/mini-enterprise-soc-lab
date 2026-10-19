# Validation results log

| Test | Evidence | Actual result | Status |
|---|---|---|---|
| 3 systemd services | `systemctl is-active ...` | active / active / active, user terminal output | Observed |
| Endpoint E2E detection | Finding `fe92e604e9d2a74957559197` | Rule 100410, original agent 001 | Observed |
| AD live finding | Finding `2e12ff986ddf9ba1bfb06375` | Rule 100411, original agent 002 | Observed |
| CASE-001 integrity | `sha256sum -c evidence/sysmon-events.sha256` | OK | Verified by operator |
| CASE-002 integrity | `sha256sum -c evidence/ad-events.sha256` | OK | Verified by operator |
| CASE-001 Run-key cleanup | Read-only check of original account hive | Output not attached yet | Pending |
| CASE-002 current account state | DC01 AD read-only commands | User reported expected behavior; no saved output yet | Needs artifact |
| SOC L1→L2 handoff | Written exercise ticket | Draft exists; no SOC L2 acknowledgement claimed | Tabletop draft |

All tested behavior occurred in a **controlled simulation**, not a production incident. Update this document with new actual evidence only; do not assume future checks succeeded.
