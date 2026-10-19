# SOC Lab architecture

**Three VirtualBox machines on a dedicated test network.** Ubuntu Wazuh Manager: `192.168.56.10`; Windows 10 agent 001: `192.168.56.20`; Windows Server DC01 agent 002: `192.168.56.30`.

## Collection layer

- Endpoint Sysmon (process creation, network connection, registry value set), Windows Security, PowerShell Operational, Defender and FIM channels, as configured in the lab.
- DC01 Windows Security 4720 (account created), 4728 (member added to security-enabled global group), 4729 (member removed; investigated after detection).
- Wazuh agents deliver to the Ubuntu Manager, which archives raw JSON events.

## Correlation and forwarding

1. `soclab_live_monitor.py` tracks archived endpoint events and maintains SQLite state.
2. `soclab_endpoint_correlator.py` produces a single finding from selected Sysmon 1/3/13 activities sharing a ProcessGuid and agent within 120 seconds.
3. `soclab_ad_live_monitor.py` tracks DC01 Security events.
4. `soclab_ad_correlator.py` links 4720 and 4728 on new user SID / group identity within 300 seconds.
5. `soclab_finding_adapter.py` transforms findings into Wazuh localfile alerts for custom rules 100410/100411.
6. A Dashboard and Investigation Queue display resulting alerts and support SOC analyst triage.

## Identity distinction

The Wazuh alert's **outer** `agent.id=000` may be the Manager reading a local Adapter log. The actual Windows origin is found in `data.agent_id` and `data.agent_name`.

## Validation / caveats

Both detector services and the adapter were observed `active`. Endpoint live controlled simulation validated real log ingestion; AD simulated creation/group-addition produced an alert and a removal event was later inspected. This architecture diagram is documentation and does not prove all configurations can be recreated without adaptation.
