# Final acceptance checklist

Treat each box as an evidence-backed check; do not tick based only on expectation.

## Detection pipeline
- [ ] Wazuh agents 001/002 show healthy connectivity
- [x] Prior observation: `soclab-endpoint`, `soclab-ad`, `soclab-adapter` showed `active`
- [x] Historical CASE-001 finding `fe92e604e9d2a74957559197` reached Wazuh rule 100410
- [x] Historical CASE-002 finding `2e12ff986ddf9ba1bfb06375` reached Wazuh rule 100411
- [ ] Dashboard panels and Investigation Queue rechecked on final publication day

## Evidence and analysis
- [x] CASE-001 file `sysmon-events.jsonl` verified with existing SHA-256 manifest by operator
- [x] CASE-002 file `ad-events.jsonl` verified with existing SHA-256 manifest by operator
- [x] CASE-002 includes three Security events 4720/4728/4729, with matching SID logic
- [ ] Confirm Registry test Run value absent from original account hive and save read-only output
- [ ] Preserve proof of current AD group membership read-only (if not already filed)
- [ ] Track historical clock discrepancies (~74s Endpoint, ~12h53m DC01) as limitations
- [ ] Verify reports accurately reflect actual evidence and outstanding work

## Response/tabletop
- [x] Two IR playbooks and one L1→L2 tabletop handoff document prepared
- [ ] Perform and record read-only tabletop validation, then mark complete

## Publication readiness
- [ ] Copy exact five deployed Python scripts
- [ ] Include reviewed, sanitized versions of applicable custom Wazuh rules and systemd units
- [ ] Correct outdated README claims/placeholders
- [ ] Ensure screenshots contain no secrets/personal data
- [ ] Run publication safety checker and manual review (`git diff --cached`)
- [ ] Validate GitHub remote and public/private visibility choice
- [ ] Confirm public repository README links and display
