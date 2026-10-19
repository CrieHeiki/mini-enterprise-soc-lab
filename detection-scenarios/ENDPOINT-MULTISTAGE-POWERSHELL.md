# Scenario A — PowerShell / Registry / Network sequence

- **Detection:** `ENDPOINT_MULTISTAGE_POWERSHELL`
- **Wazuh rule:** `100410` (level 10)
- **Evidence:** Sysmon 1 process creation, 13 Registry SetValue, 3 network connection
- **Correlation key:** same Windows agent + ProcessGuid
- **Time limit:** 120 seconds
- **MITRE ATT&CK:** T1059.001; T1547.001 (observed indicators, not necessarily successful persistence)
- **Validation:** controlled local simulation with test Run key, `notepad.exe` value data, lab-only TCP listener `192.168.56.10:18080`.
- **Case:** [CASE-001](../incident-reports/CASE-001/CASE-001-Endpoint-PowerShell-Investigation.md)

True positive for rule behavior ≠ confirmed compromise. Sysmon 3 shows a connection, not content exfiltration. Record time discrepancy (~74s) in multi-host investigations. Independent registry cleanup verification is required before closing the case.
