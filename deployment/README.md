# Deployment notes (documentation, not a one-click installer)

## Platform and components

- Hypervisor: VirtualBox on Windows 11 host.
- Wazuh Manager observed: 4.14.8 on Ubuntu (confirm versions before publishing).
- Windows 10 Home Wazuh agent 001 with Sysmon and Windows log sources; Windows Server 2022 DC01 agent 002 with Security auditing.
- Python correlators / live monitors / adapter use SQLite state and JSONL findings; three systemd services observed active.

## Starting point: read-only validation

```bash
sudo /var/ossec/bin/agent_control -l
sudo systemctl is-active soclab-endpoint soclab-ad soclab-adapter
sudo systemctl cat soclab-endpoint soclab-ad soclab-adapter
```

## Manager and Agent configuration

Review Wazuh Manager's `/var/ossec/etc/ossec.conf`, Windows Agent `ossec.conf`, archive JSON collection, channel collection and Sysmon policy. **Do not publish complete production config files, credentials, agent keys, authentication tokens or enrollment secrets.** Prepare redacted, non-deployable examples if needed.

## Custom rules and systemd units

- See [Wazuh rule documentation](wazuh-rules/README.md) and [service deployment](systemd/README.md).
- Prefer to publish only reviewed custom rules and portable service *examples*, not the entire installation directory.

## Reproduction safety

Use only isolated VMs or accounts you own/control. Domain Admins events can be created by an administrator in an authorized lab but should not be reproduced in third-party environments. Revalidate event channels, timestamps and agent metadata after installation.
