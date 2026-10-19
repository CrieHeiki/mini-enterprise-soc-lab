#!/usr/bin/env python3
"""Incremental AD (4720 + 4728) correlation from Wazuh archives.json.

Independent of the existing endpoint live monitor: separate SQLite DB/output.
Run --from-start --once on a sample; without --from-start, new archives start at EOF.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from datetime import timezone

from soclab_ad_correlator import (detect, event_id, event_time, host_id,
                                 identity, is_relevant)

MAX_LINES = 1000
RETENTION_SECONDS = 3600  # Keep a one-hour event-time context for a 5-min window.


def open_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path))
    db.executescript('''
    CREATE TABLE IF NOT EXISTS cursor (
      path TEXT PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER);
    CREATE TABLE IF NOT EXISTS events (
      fingerprint TEXT PRIMARY KEY, host TEXT, member_sid TEXT,
      ts REAL, payload TEXT);
    CREATE INDEX IF NOT EXISTS events_group ON events(host,member_sid);
    CREATE INDEX IF NOT EXISTS events_time ON events(ts);
    CREATE TABLE IF NOT EXISTS findings (
      finding_id TEXT PRIMARY KEY, payload TEXT NOT NULL, delivered INTEGER DEFAULT 0);
    ''')
    return db


def read_position(db, path, from_start):
    stat = path.stat()
    saved = db.execute('SELECT device,inode,offset FROM cursor WHERE path=?',
                       (str(path),)).fetchone()
    if saved and saved[0] == stat.st_dev and saved[1] == stat.st_ino and saved[2] <= stat.st_size:
        return saved[2], stat.st_dev, stat.st_ino
    # New monitor tails; rotated/truncated source must restart at byte 0.
    return (0 if from_start or saved else stat.st_size), stat.st_dev, stat.st_ino


def add_event(db, event):
    payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    fp = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    host = host_id(event)
    sid = identity(event)
    ts = event_time(event).astimezone(timezone.utc).timestamp()
    result = db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)',
                        (fp, host, sid, ts, payload))
    return (host, sid) if result.rowcount else None


def analyze(db, host, sid, window):
    rows = db.execute('SELECT payload FROM events WHERE host=? AND member_sid=?',
                      (host, sid)).fetchall()
    found = detect([json.loads(row[0]) for row in rows], window=window)
    for f in found:
        db.execute('INSERT OR IGNORE INTO findings(finding_id,payload) VALUES (?,?)',
                   (f['finding_id'], json.dumps(f, ensure_ascii=False)))


def scan_batch(db, archive, agent, window, from_start=False):
    start, dev, inode = read_position(db, archive, from_start)
    scanned, changed = 0, set()
    with archive.open('rb') as f:
        f.seek(start)
        for _ in range(MAX_LINES):
            offset = f.tell()
            raw = f.readline()
            if not raw or not raw.endswith(b'\n'):
                f.seek(offset)
                break
            scanned += 1
            try:
                ev = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                print(f'WARN bad JSON at offset {offset}: {exc}', file=sys.stderr)
                continue
            if (ev.get('agent', {}).get('name') == agent or
                str(ev.get('agent', {}).get('id')) == agent) and is_relevant(ev):
                key = add_event(db, ev)
                if key:
                    changed.add(key)
        new_offset = f.tell()

    for host, sid in changed:
        analyze(db, host, sid, window)
    if changed:
        newest = db.execute('SELECT MAX(ts) FROM events').fetchone()[0]
        if newest is not None:
            db.execute('DELETE FROM events WHERE ts < ?',
                       (newest - RETENTION_SECONDS,))
    db.execute('''INSERT INTO cursor VALUES (?,?,?,?)
                  ON CONFLICT(path) DO UPDATE SET device=excluded.device,
                  inode=excluded.inode,offset=excluded.offset''',
               (str(archive), dev, inode, new_offset))
    db.commit()
    return scanned


def deliver(db, output):
    rows = db.execute('SELECT finding_id,payload FROM findings WHERE delivered=0 ORDER BY rowid').fetchall()
    if not rows:
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('a', encoding='utf-8') as f:
        for fid, payload in rows:
            f.write(payload + '\n')
            f.flush()
            os.fsync(f.fileno())
            db.execute('UPDATE findings SET delivered=1 WHERE finding_id=?', (fid,))
            db.commit()
            print(f'AD FINDING: {fid}', flush=True)
    return len(rows)


def pump(db, archive, output, agent, window, from_start=False):
    total = 0
    while True:
        got = scan_batch(db, archive, agent, window, from_start)
        total += got
        if got < MAX_LINES:
            break
    return total, deliver(db, output)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--archive', type=Path, default=Path('/var/ossec/logs/archives/archives.json'))
    ap.add_argument('--db', type=Path, default=Path('state/ad-monitor.sqlite'))
    ap.add_argument('--output', type=Path, default=Path('output/ad_findings_live.jsonl'))
    ap.add_argument('--agent', default='DC01', help='Wazuh Agent name or ID for Domain Controller')
    ap.add_argument('--window', type=int, default=300)
    ap.add_argument('--poll', type=float, default=2)
    ap.add_argument('--from-start', action='store_true')
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()
    if not 0 < args.window < RETENTION_SECONDS:
        ap.error(f'window must be 1..{RETENTION_SECONDS - 1}')
    if args.poll <= 0:
        ap.error('poll must be positive')

    os.umask(0o077)
    archive, dbfile, output = (p.expanduser().resolve() for p in
                               (args.archive, args.db, args.output))
    db = open_db(dbfile)
    print(f'AD monitor watching {archive} for {args.agent}', flush=True)
    try:
        while True:
            if archive.exists():
                scanned, published = pump(db, archive, output, args.agent, args.window,
                                          args.from_start)
                if scanned or published:
                    print(f'Scanned {scanned} new lines; published {published} AD findings.', flush=True)
            elif args.once:
                raise FileNotFoundError(archive)
            else:
                print('WARN archive does not exist; waiting', file=sys.stderr)
            if args.once:
                break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print('Stopped.')
    finally:
        db.close()


if __name__ == '__main__':
    main()
