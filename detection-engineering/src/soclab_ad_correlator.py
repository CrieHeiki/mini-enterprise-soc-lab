#!/usr/bin/env python3
"""Correlate AD user creation (4720) with Domain Admins membership (4728).

Input: Wazuh archives.json JSONL. This is an investigation finding, not proof
of compromise. No third-party dependencies.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

DOMAIN_ADMIN_SID = re.compile(r'^S-1-5-21-\d+-\d+-\d+-512$', re.I)
ACCOUNT_SID = re.compile(r'^S-1-5-21-\d+-\d+-\d+-\d+$', re.I)


def event_id(event):
    return str(event.get('data', {}).get('win', {}).get('system', {}).get('eventID', ''))


def eventdata(event):
    return event.get('data', {}).get('win', {}).get('eventdata', {})


def system(event):
    return event.get('data', {}).get('win', {}).get('system', {})


def host_id(event):
    a = event.get('agent', {})
    return str(a.get('id') or a.get('name') or '').strip()


def event_time(event):
    raw = system(event).get('systemTime') or event.get('timestamp')
    if not raw:
        return None
    try:
        result = datetime.fromisoformat(str(raw).replace('Z', '+00:00'))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def normalize_sid(value):
    return str(value or '').strip().upper()


def identity(event):
    """User SID for 4720; added member SID for 4728."""
    d = eventdata(event)
    if event_id(event) == '4720':
        return normalize_sid(d.get('targetSid'))
    if event_id(event) == '4728':
        return normalize_sid(d.get('memberSid'))
    return ''


def is_relevant(event):
    if event_id(event) not in {'4720', '4728'}:
        return False
    if str(system(event).get('channel', '')).lower() != 'security':
        return False
    if not host_id(event) or event_time(event) is None:
        return False
    sid = identity(event)
    if not ACCOUNT_SID.fullmatch(sid):
        return False
    if event_id(event) == '4728':
        group_sid = normalize_sid(eventdata(event).get('targetSid'))
        return bool(DOMAIN_ADMIN_SID.fullmatch(group_sid) and
                    group_sid.rsplit('-', 1)[0] == sid.rsplit('-', 1)[0])
    return True


def evidence(event):
    sys = system(event)
    return {
        'event_id': event_id(event),
        'event_record_id': sys.get('eventRecordID'),
        'event_time': event_time(event).isoformat(),
        'source_host': sys.get('computer'),
    }


def _finding(created, added):
    account_sid = identity(created)
    host = host_id(created)
    dt = round((event_time(added) - event_time(created)).total_seconds(), 3)
    cdata, adata = eventdata(created), eventdata(added)
    # Event timestamps and record IDs distinguish legitimate multiple events,
    # while making the finding deterministic when archives are replayed.
    key = '|'.join([
        'AD_PRIVILEGE_ESCALATION', host, account_sid,
        str(system(created).get('eventRecordID') or event_time(created).isoformat()),
        str(system(added).get('eventRecordID') or event_time(added).isoformat()),
    ])
    return {
        'soclab_detection': 'AD_PRIVILEGE_ESCALATION',
        'finding_id': hashlib.sha256(key.encode('utf-8')).hexdigest()[:24],
        'severity': 'high',
        'assessment': 'New AD account added to Domain Admins; investigate authorization',
        'agent_id': host,
        'agent_name': created.get('agent', {}).get('name'),
        'account_sid': account_sid,
        'account_name': cdata.get('targetUserName'),
        'account_domain': cdata.get('targetDomainName'),
        'group_name': adata.get('targetUserName'),
        'group_sid': normalize_sid(adata.get('targetSid')),
        'created_by': cdata.get('subjectUserName'),
        'added_by': adata.get('subjectUserName'),
        'time_difference_seconds': dt,
        'mitre_technique': 'T1098',
        'evidence': [evidence(created), evidence(added)],
    }


def detect(events, window=300):
    """Return one finding per qualifying 4720->4728 pair (same host & SID).

    Input ordering does not matter. 4728 must occur 0..window seconds after 4720.
    """
    if not 0 < window <= 86400:
        raise ValueError('window must be in 1..86400 seconds')
    grouped = defaultdict(lambda: {'4720': [], '4728': []})
    for ev in events:
        if is_relevant(ev):
            grouped[(host_id(ev), identity(ev))][event_id(ev)].append(ev)

    results = {}
    for _, per_type in grouped.items():
        created = sorted(per_type['4720'], key=event_time)
        added = sorted(per_type['4728'], key=event_time)
        for membership in added:
            candidates = [ev for ev in created if
                          0 <= (event_time(membership) - event_time(ev)).total_seconds() <= window]
            if not candidates:
                continue
            finding = _finding(candidates[-1], membership)
            results[finding['finding_id']] = finding
    return sorted(results.values(), key=lambda x: x['evidence'][1]['event_time'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input', type=Path, help='JSONL file containing 4720 and 4728')
    ap.add_argument('output', type=Path, help='Destination findings JSONL')
    ap.add_argument('--window', type=int, default=300, help='Seconds (default 300)')
    args = ap.parse_args()
    events = []
    with args.input.open(encoding='utf-8') as f:
        for number, line in enumerate(f, start=1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    ap.error(f'Invalid JSON at line {number}: {exc}')
    findings = detect(events, args.window)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8') as f:
        for item in findings:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(f'Processed {len(events)} events. AD findings: {len(findings)}')


if __name__ == '__main__':
    main()
