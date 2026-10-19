# Scenario B — New domain account becomes Domain Admin

- **Detection:** `AD_PRIVILEGE_ESCALATION`
- **Wazuh rule:** `100411` (level 12)
- **Trigger:** Windows Security 4720 new account + 4728 group addition
- **Keys:** same DC agent, 4720 `targetSid` = 4728 `memberSid`; group SID ends in RID 512
- **Time limit:** 300 seconds
- **Follow-up evidence:** 4729 (removal, not a detection trigger)
- **MITRE ATT&CK:** T1136.002 and T1098.007 are useful context; verify actual mapping against code/rules.
- **Case:** [CASE-002](../incident-reports/CASE-002/CASE-002-AD-Privilege-Escalation-Investigation.md)

In the analyzed controlled scenario, account creation -> group addition took 8.582s, and group membership was removed ~5.040s later. A short-lived membership event is not proof of credential misuse or session compromise. Historical clocks differed by ~12h53m between DC01 source event time and Wazuh archive time; retain both timestamps.
