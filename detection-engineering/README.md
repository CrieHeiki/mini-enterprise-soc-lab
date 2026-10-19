# Python detection and monitoring

Source directory: [`src/`](src/). Copy the **current deployed** five Python files from `/opt/soclab/`. Past versions of the endpoint correlator lacked `agent_name`; the current deployed version should emit the source endpoint's name.

| File | Purpose |
|---|---|
| `soclab_endpoint_correlator.py` | Correlate Sysmon IDs 1/3/13 by ProcessGuid/source agent within 120 s |
| `soclab_live_monitor.py` | Stateful endpoint processing / SQLite and JSONL |
| `soclab_ad_correlator.py` | Detect newly created AD account being added to Domain Admins within 300 s |
| `soclab_ad_live_monitor.py` | Stateful DC01 processing / SQLite and JSONL |
| `soclab_finding_adapter.py` | Convert finding objects to Wazuh-readable local JSONL alerts |

No DBs, live logs, service credentials, or private environment data are needed to demonstrate the code. Document source file dependencies based on the version actually published. Do not publish historical code while claiming it is deployed.

## Demonstrated pipeline

`Wazuh archive -> live monitor -> Python correlation -> JSONL finding -> adapter -> Wazuh custom rule -> Dashboard`.

## Source review before publish

Inspect imports and paths, verify that scripts contain no embedded secrets, check for IPs/identities, and mark actual runtime dependencies. Preserve deployed scripts separately; sanitize only the repository copies.
