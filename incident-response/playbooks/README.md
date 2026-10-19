# SOC-Lab — Incident Response Playbooks (Phase 5.8)

Two **SOC Tier 1-focused**, evidence-based response playbooks for the Mini Enterprise SOC project. They translate the completed investigation cases into repeatable detection, triage, escalation and controlled recovery workflows. They are **lab-only demonstration procedures**, not automatic authorization for production containment.

| Playbook | Wazuh trigger | Investigated case | Core detection |
|---|---|---|---|
| [IR-001 — PowerShell Endpoint Response](IR-001-PowerShell-Endpoint-Response.md) | `100410` | CASE-001 | Sysmon 1 + 3 + 13, same ProcessGuid within 120 s |
| [IR-002 — AD Privilege Response](IR-002-AD-Privilege-Response.md) | `100411` | CASE-002 | Security 4720 + 4728, same SID within 300 s; 4729 follow-up evidence |

Supplementary files:

- [HANDOFF-TEMPLATE.md](HANDOFF-TEMPLATE.md): consistent SOC L1 → L2 escalation ticket.
- [VALIDATION-CHECKLIST.md](VALIDATION-CHECKLIST.md): **read-only** lab tabletop validation and sign-off checklist.

## Scope, behavior and controls

1. **Detect**: inspect Wazuh alert, obtain original source agent information from `data.agent_*` fields, and validate detection evidence.
2. **Respond**: classify and triage with contextual facts, preserve raw logs and hashes, document status, and escalate unknown/unauthorized actions.
3. **Recover / improve**: approved owner performs any containment/remediation; analyst validates evidence and writes follow-up detection improvements.

This structure is aligned to NIST SP 800-61 Revision 3's incident response lifecycle framing (Detect, Respond, Recover). Reference: https://csrc.nist.gov/pubs/sp/800/61/r3/final

**Do not** automatically isolate hosts, disable users, delete logs, modify AD groups, reset privileged passwords, or alter firewall policy as a Tier 1 verification activity. Current incidents require appropriate decision makers and change controls.

## How to use in the user's SOC Lab

Recommended GitHub tree:

```text
SOC-Lab/
├── incident-reports/
│   ├── CASE-001/
│   │   ├── CASE-001-Endpoint-PowerShell-Investigation.md
│   │   └── evidence/                 # PRIVATE/raw; publish sanitized examples only
│   └── CASE-002/
│       ├── CASE-002-AD-Privilege-Escalation-Investigation.md
│       └── evidence/                 # PRIVATE/raw; publish sanitized examples only
└── incident-response/
    └── playbooks/
        ├── README.md
        ├── IR-001-PowerShell-Endpoint-Response.md
        ├── IR-002-AD-Privilege-Response.md
        ├── HANDOFF-TEMPLATE.md
        └── VALIDATION-CHECKLIST.md
```

> **Relative links:** Links to CASE-001 and CASE-002 use the final GitHub tree shown above (`../../incident-reports/...`). Those report files are **not** included in this Phase 5.8 bundle; place the reports in the indicated paths so the links work.

## Lab-specific observations you must not lose

- CASE-001 is an **authorized simulation** (`integration_test=false` means only *not adapter replay*). Registry cleanup and historical 74-second source/ingest clock difference require proper documentation.
- CASE-002 includes a verified Event **4729** (Domain Admins member removed ~5 s after addition). Initial account-creation event shows disabled state **at creation** only. Historic DC01 source vs Wazuh archive differs by ~12 h 53 m despite later NTP checks showing synchrony.
- Raw Windows Security/Sysmon logs may contain sensitive internal context; sanitize before public upload. Never invent logs or imply actual compromise.

## Definition of done

Phase 5.8 is ready for sign-off when both playbooks are added to the repository, the read-only validation checklist has been executed with actual outputs, and at least one mock handoff demonstrates appropriate L1→L2 escalation. Containment execution is **not required** for a lab tabletop validation.
