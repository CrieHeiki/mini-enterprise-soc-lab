# Wazuh custom detection rules

The lab uses correlation alerts `100410` (endpoint) and `100411` (Active Directory) and other custom rules. Before publishing any `.xml` file:

1. Identify the file actually loaded by Wazuh (`sudo grep -R -nE '100410|100411|100220' /var/ossec/etc/rules/`).
2. Copy **only custom rule definitions needed for this project**, not Wazuh built-in rule packages.
3. Inspect and remove credentials, external endpoints and personal information.
4. Use a separate test/lab Wazuh environment before distributing any example as installable.
5. **Metadata review:** a domain account creation event `4720` should not be documented as `T1136.001 Local Account`; consider `T1136.002 Domain Account` for the appropriate context, and validate that rule metadata is accurate.

**No rules have been included automatically in this template**: they must match the deployed lab source and be reviewed first.
