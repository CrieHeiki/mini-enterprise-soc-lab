# Live-monitoring service units

Read-only inspection on Wazuh Manager:

```bash
sudo systemctl cat soclab-endpoint
sudo systemctl cat soclab-ad
sudo systemctl cat soclab-adapter
sudo systemctl is-active soclab-endpoint soclab-ad soclab-adapter
```

For publication, copy actual unit files to this folder as **examples** after reviewing each `ExecStart`, `User`, `Group`, `Environment`, `EnvironmentFile`, `WorkingDirectory`, directory permission and local secret path. Consider neutral paths or documented placeholders; do not suggest the examples are deployable unchanged if paths are hardcoded to your VM.

**Never edit or restart a live service just to prepare a GitHub copy.**
