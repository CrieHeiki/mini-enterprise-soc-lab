# Publication security checklist

This repository is intended for a **portfolio**, and the source VM is an isolated SOC lab. Before making the GitHub repository public:

1. **Never commit:** `/var/ossec/etc/client.keys`, Wazuh secrets, enrollment tokens, API credentials, `.env`, SSH private keys, system exports, raw incident `*.jsonl`, `.db` / `.sqlite`, internal credential files, VM disk images, or whole Wazuh configuration trees.
2. Review the five copied Python scripts individually for hardcoded credentials, email, personally identifying information, IPs, absolute usernames/paths and shell invocations. Replace sensitive data in **repo copies only**, not deployed scripts.
3. Review copied `.service` files for `Environment=...`, `EnvironmentFile=...`, and internal permissions/paths; redact secrets and label examples when no longer directly deployable.
4. Publish custom Wazuh rules only after line-by-line review; never automatically copy all Wazuh system configuration.
5. Reports should be reviewed for lab user SIDs, command lines, personal usernames and addresses. Keep original JSONL privately under `~/SOC-Lab/`.
6. Review each screenshot before staging and avoid showing unrelated private data.
7. Run `python3 scripts/check_publish_ready.py`, then `git status --short`, `git diff --cached --stat`, `git diff --cached` and `git diff --cached --check` locally. Automated scanners may miss secrets.
8. If you accidentally commit a credential, **revoke/rotate it immediately**, stop before pushing, and clean Git history. A `.gitignore` added later does not erase previous commits.

Protect your GitHub SSH **private** key (`~/.ssh/id_ed25519*`). GitHub only needs the **public** `.pub` file.
