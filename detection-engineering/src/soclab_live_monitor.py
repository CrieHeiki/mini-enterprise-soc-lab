#!/usr/bin/env python3
"""Incremental Wazuh archives.json monitor for endpoint correlation (lab MVP).

Reads only new, complete JSONL lines; persists input cursor and event window in SQLite.
Uses soclab_endpoint_correlator.detect for actual detection logic.
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

from soclab_endpoint_correlator import detect, eid, etime, fields

EVENT_IDS = {"1", "3", "13"}
RETENTION_SECONDS = 600  # Keep 10 minutes of event-time context, > 120s detection window.
BATCH_LINES = 1000


def prepare_db(db_path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cursor (
          path TEXT PRIMARY KEY, device INTEGER NOT NULL,
          inode INTEGER NOT NULL, offset INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
          event_hash TEXT PRIMARY KEY, host TEXT NOT NULL,
          guid TEXT NOT NULL, event_epoch REAL NOT NULL,
          payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS event_by_process ON events(host, guid);
        CREATE INDEX IF NOT EXISTS event_by_time ON events(event_epoch);
        CREATE TABLE IF NOT EXISTS findings (
          finding_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
          delivered INTEGER NOT NULL DEFAULT 0
        );
    """)
    return conn


def archive_ident(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size)


def get_start_position(conn, path, from_start=False):
    device, inode, size = archive_ident(path)
    saved = conn.execute("SELECT device,inode,offset FROM cursor WHERE path=?", (str(path),)).fetchone()
    if saved is not None and saved[0] == device and saved[1] == inode and saved[2] <= size:
        return saved[2], device, inode
    # First live start tails new records only. Replay starts at 0 when --from-start.
    return (0 if from_start or saved is not None else size), device, inode


def relevant(event, agent_name):
    if event.get("agent", {}).get("name") != agent_name:
        return False
    if event.get("data", {}).get("win", {}).get("system", {}).get("channel") != "Microsoft-Windows-Sysmon/Operational":
        return False
    return eid(event) in EVENT_IDS and bool(fields(event).get("processGuid")) and etime(event) is not None


def add_event(conn, event):
    host = str(event.get("agent", {}).get("id") or event.get("agent", {}).get("name") or "")
    guid = str(fields(event).get("processGuid", "")).lower()
    timestamp = etime(event)
    if not host or not guid or timestamp is None:
        return None
    # Canonical event fingerprint prevents a replay of the same line inserting it again.
    encoded = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    fp = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    ts = timestamp.astimezone(timezone.utc).timestamp()
    cur = conn.execute(
        "INSERT OR IGNORE INTO events(event_hash,host,guid,event_epoch,payload) VALUES (?,?,?,?,?)",
        (fp, host, guid, ts, encoded),
    )
    return (host, guid) if cur.rowcount else None


def analyze_process(conn, host, guid, window):
    rows = conn.execute("SELECT payload FROM events WHERE host=? AND guid=?", (host, guid)).fetchall()
    if not rows:
        return 0
    found = detect([json.loads(row[0]) for row in rows], window=window)
    new_count = 0
    for finding in found:
        result = conn.execute(
            "INSERT OR IGNORE INTO findings(finding_id,payload) VALUES(?,?)",
            (finding["finding_id"], json.dumps(finding, ensure_ascii=False)),
        )
        new_count += int(result.rowcount > 0)
    return new_count


def process_batch(conn, path, agent_name, window, from_start=False):
    start, device, inode = get_start_position(conn, path, from_start)
    changed = set()
    read_lines = 0
    new_findings = 0
    # Snapshot-based reads; do not process a partial JSONL line.
    with path.open("rb") as handle:
        handle.seek(start)
        for _ in range(BATCH_LINES):
            before = handle.tell()
            raw = handle.readline()
            if not raw or not raw.endswith(b"\n"):
                handle.seek(before)
                break
            read_lines += 1
            try:
                evt = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                print(f"WARN: skipping invalid JSON line at byte {before}: {exc}", file=sys.stderr)
                continue
            if relevant(evt, agent_name):
                key = add_event(conn, evt)
                if key:
                    changed.add(key)
        new_offset = handle.tell()

    for host, guid in changed:
        new_findings += analyze_process(conn, host, guid, window)

    if changed:
        max_row = conn.execute("SELECT MAX(event_epoch) FROM events").fetchone()[0]
        if max_row is not None:
            conn.execute("DELETE FROM events WHERE event_epoch < ?", (max_row - RETENTION_SECONDS,))

    conn.execute("""INSERT INTO cursor(path,device,inode,offset) VALUES(?,?,?,?)
                 ON CONFLICT(path) DO UPDATE SET
                 device=excluded.device,inode=excluded.inode,offset=excluded.offset""",
                 (str(path), device, inode, new_offset))
    conn.commit()
    return read_lines, new_findings


def deliver_findings(conn, output_path):
    rows = conn.execute("SELECT finding_id,payload FROM findings WHERE delivered=0 ORDER BY rowid").fetchall()
    if not rows:
        return 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("a", encoding="utf-8") as handle:
        for fid, payload in rows:
            handle.write(payload + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            conn.execute("UPDATE findings SET delivered=1 WHERE finding_id=?", (fid,))
            conn.commit()
            count += 1
            finding = json.loads(payload)
            print(f"FINDING {fid}: {finding['soclab_detection']} on {finding['agent_id']}", flush=True)
    return count


def pump(conn, archive, output, agent_name, window, from_start=False):
    total = 0
    while True:
        scanned, _ = process_batch(conn, archive, agent_name, window, from_start=from_start)
        total += scanned
        if scanned < BATCH_LINES:
            break
    delivered = deliver_findings(conn, output)
    return total, delivered


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive", type=Path, default=Path("/var/ossec/logs/archives/archives.json"))
    ap.add_argument("--db", type=Path, default=Path("state/soclab.db"))
    ap.add_argument("--output", type=Path, default=Path("output/findings_live.jsonl"))
    ap.add_argument("--agent", default="WIN10-ENDPOINT01")
    ap.add_argument("--window", type=int, default=120)
    ap.add_argument("--poll", type=float, default=2.0)
    ap.add_argument("--from-start", action="store_true", help="Read existing records on first run (replay/test)")
    ap.add_argument("--once", action="store_true", help="Process current archive, then exit")
    args = ap.parse_args()
    if args.window <= 0 or args.window >= RETENTION_SECONDS:
        ap.error(f"--window must be in 1..{RETENTION_SECONDS-1} seconds")
    if args.poll <= 0:
        ap.error("--poll must be positive")
    os.umask(0o077)
    archive = args.archive.expanduser().resolve()
    output = args.output.expanduser().resolve()
    conn = prepare_db(args.db.expanduser().resolve())
    print(f"Monitoring {archive} for agent {args.agent}; database {args.db}", flush=True)
    try:
        while True:
            if not archive.exists():
                if args.once:
                    raise FileNotFoundError(archive)
                print(f"WARN archive missing: {archive}; retrying", file=sys.stderr)
            else:
                scanned, findings = pump(conn, archive, output, args.agent, args.window, args.from_start)
                if scanned or findings:
                    print(f"Scanned {scanned} new lines; published {findings} finding(s).", flush=True)
            if args.once:
                break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
