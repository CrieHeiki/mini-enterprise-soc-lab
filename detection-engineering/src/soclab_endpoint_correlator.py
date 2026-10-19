#!/usr/bin/env python3
"""Analyze a Wazuh JSONL sample to find encoded PowerShell + network + Run key."""
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import re

ENCODED = re.compile(r'(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?=\s|$)')
RUN_KEY = re.compile(r'\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\', re.I)


def eid(e):
    return str(e.get('data', {}).get('win', {}).get('system', {}).get('eventID', ''))


def fields(e):
    return e.get('data', {}).get('win', {}).get('eventdata', {})


def etime(e):
    system = e.get('data', {}).get('win', {}).get('system', {})
    raw = system.get('systemTime') or e.get('timestamp', '')
    try:
        return datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


def encoded_powershell(e):
    image = str(fields(e).get('image', '')).replace('\\\\', '\\').lower()
    command = str(fields(e).get('commandLine', ''))
    return (image.endswith('\\powershell.exe') or image.endswith('\\pwsh.exe')) and bool(ENCODED.search(command))


def registry_run(e):
    path = str(fields(e).get('targetObject', '')).replace('\\\\', '\\')
    return bool(RUN_KEY.search(path))


def evidence(e):
    system = e.get('data', {}).get('win', {}).get('system', {})
    return {'event_id': eid(e), 'event_record_id': system.get('eventRecordID'),
            'event_time': etime(e).isoformat()}


def detect(events, window=120):
    grouped = defaultdict(list)
    for e in events:
        agent = e.get('agent', {})
        host = str(agent.get('id') or agent.get('name') or '')
        guid = str(fields(e).get('processGuid') or '').lower()
        if host and guid and eid(e) in {'1', '3', '13'} and etime(e):
            grouped[(host, guid)].append(e)

    findings = []
    for (host, guid), group in grouped.items():
        for proc in group:
            if eid(proc) != '1' or not encoded_powershell(proc):
                continue
            start = etime(proc)
            def within(e):
                return 0 <= (etime(e) - start).total_seconds() <= window
            net = next((e for e in group if eid(e) == '3' and within(e)
                        and fields(e).get('destinationIp')), None)
            reg = next((e for e in group if eid(e) == '13' and within(e)
                        and registry_run(e)), None)
            if net is None or reg is None:
                continue
            identity = f'ENDPOINT_MULTISTAGE|{host}|{guid}'
            findings.append({
                'soclab_detection': 'ENDPOINT_MULTISTAGE_POWERSHELL',
                'finding_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
                'severity': 'high',
                'assessment': 'Suspicious activity, not proof of compromise',
                'agent_id': host,
		'agent_name': proc.get('agent', {}).get('name'),
		'process_guid': guid,
                'destination_ip': fields(net).get('destinationIp'),
                'destination_port': fields(net).get('destinationPort'),
                'registry_target': fields(reg).get('targetObject'),
                'evidence': [evidence(proc), evidence(net), evidence(reg)],
            })
            break  # Deduplicate per agent + process GUID.
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='Input Wazuh archive subset (.jsonl)')
    ap.add_argument('output', help='Output findings (.jsonl)')
    ap.add_argument('--window', type=int, default=120)
    args = ap.parse_args()
    with open(args.input, encoding='utf8') as f:
        events = [json.loads(line) for line in f if line.strip()]
    findings = detect(events, args.window)
    with open(args.output, 'w', encoding='utf8') as f:
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False) + '\n')
    print(f'Processed {len(events)} events. Findings: {len(findings)}')

if __name__ == '__main__':
    main()
