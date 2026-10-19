#!/usr/bin/env python3
"""Forward Python detection findings into the Wazuh Manager JSON log input.

Inputs: one JSON object per line, emitted by existing SOC-Lab monitors.
Output: flattened JSONL compatible with Wazuh JSON decoder (no nested arrays).
Uses SQLite input cursors and a pending-delivery outbox for restart resilience.

This lab adapter offers at-least-once publication, not exactly-once; consumers
should use finding_id + soclab_detection to suppress rare retry duplicates.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

DETECTIONS = {"AD_PRIVILEGE_ESCALATION", "ENDPOINT_MULTISTAGE_POWERSHELL"}
CHUNK_LIMIT = 2000


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cursors (
            source TEXT PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER
        );
        CREATE TABLE IF NOT EXISTS outbound (
            detection TEXT NOT NULL, finding_id TEXT NOT NULL,
            payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (detection, finding_id)
        );
    """)
    return conn


def compact_evidence(finding: dict) -> dict:
    """Wazuh's JSON decoder should not receive arrays of objects."""
    evidence = finding.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    entries = [item for item in evidence if isinstance(item, dict)]
    def join(field: str) -> str:
        return ",".join(str(x[field]) for x in entries if x.get(field) is not None)
    return {
        "evidence_event_ids": join("event_id"),
        "evidence_record_ids": join("event_record_id"),
        "evidence_times": join("event_time"),
        "evidence_count": len(entries),
    }


def flat_finding(finding: dict, source_name: str, replay: bool = False) -> dict:
    """Whitelist scalar fields; retain detailed evidence in the original source."""
    detection = finding.get("soclab_detection")
    fid = finding.get("finding_id")
    if detection not in DETECTIONS or not isinstance(fid, str) or not fid:
        raise ValueError("Unsupported soclab_detection or missing finding_id")

    fields = (
        "severity", "assessment", "agent_id", "agent_name", "process_guid",
        "destination_ip", "destination_port", "registry_target", "account_sid",
        "account_name", "account_domain", "group_sid", "group_name",
        "created_by", "added_by", "time_difference_seconds", "mitre_technique",
    )
    result = {
        "soclab_detection": detection,
        "finding_id": fid,
        "source_monitor": source_name,
        "integration_test": bool(replay),
    }
    for key in fields:
        val = finding.get(key)
        if val is not None and isinstance(val, (str, int, float, bool)):
            result[key] = val
    result.update(compact_evidence(finding))
    return result


def position(db: sqlite3.Connection, path: Path, from_start: bool):
    stat = path.stat()
    saved = db.execute("SELECT device,inode,offset FROM cursors WHERE source=?", (str(path),)).fetchone()
    if saved and saved[0] == stat.st_dev and saved[1] == stat.st_ino and saved[2] <= stat.st_size:
        return saved[2], stat
    # Never re-read existing findings when enabling the adapter for the first time.
    # If a previously-read file rotated/truncated, restart from its beginning.
    start = 0 if from_start or saved else stat.st_size
    return start, stat


def ingest(db: sqlite3.Connection, path: Path, from_start: bool, replay: bool) -> int:
    if not path.exists():
        return 0
    start, stat = position(db, path, from_start)
    staged = 0
    with path.open("rb") as reader:
        reader.seek(start)
        for _ in range(CHUNK_LIMIT):
            line_start = reader.tell()
            data = reader.readline()
            if not data or not data.endswith(b"\n"):
                reader.seek(line_start)
                break
            if not data.strip():
                continue
            try:
                finding = json.loads(data)
                flattened = flat_finding(finding, path.name, replay)
            except (ValueError, UnicodeDecodeError, TypeError) as exc:
                print(f"WARN {path}:{line_start}: invalid finding: {exc}", file=sys.stderr)
                continue
            hit = db.execute(
                "INSERT OR IGNORE INTO outbound(detection,finding_id,payload) VALUES(?,?,?)",
                (flattened["soclab_detection"], flattened["finding_id"],
                 json.dumps(flattened, ensure_ascii=False, separators=(",", ":"))),
            )
            staged += int(hit.rowcount > 0)
        end = reader.tell()
    db.execute("""INSERT INTO cursors(source,device,inode,offset) VALUES(?,?,?,?)
                  ON CONFLICT(source) DO UPDATE SET
                    device=excluded.device,inode=excluded.inode,offset=excluded.offset""",
               (str(path), stat.st_dev, stat.st_ino, end))
    db.commit()
    return staged


def deliver(db: sqlite3.Connection, output: Path) -> int:
    rows = db.execute("""SELECT detection,finding_id,payload FROM outbound
                         WHERE delivered=0 ORDER BY rowid LIMIT 2000""").fetchall()
    if not rows:
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    # Wazuh Logcollector must be able to read this log. If it exists, retain mode.
    # If adapter creates it, use mode 0644 (respecting umask chosen in main).
    with output.open("a", encoding="utf-8") as writer:
        for detection, fid, payload in rows:
            writer.write(payload + "\n")
            writer.flush()
            os.fsync(writer.fileno())
            db.execute("""UPDATE outbound SET delivered=1
                          WHERE detection=? AND finding_id=?""", (detection, fid))
            db.commit()
            print(f"SENT {detection} {fid}", flush=True)
    return len(rows)


def tick(db, sources: list[Path], output: Path, from_start=False, replay=False):
    added = 0
    for path in sources:
        while True:
            # Stop after catching up; retaining cursor handles subsequent polls.
            offset_before = db.execute("SELECT offset FROM cursors WHERE source=?", (str(path),)).fetchone()
            added += ingest(db, path, from_start, replay)
            offset_after = db.execute("SELECT offset FROM cursors WHERE source=?", (str(path),)).fetchone()
            if not path.exists() or offset_before == offset_after:
                break
            if offset_after and offset_after[0] >= path.stat().st_size:
                break
    return added, deliver(db, output)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", type=Path, default=Path("/var/log/soclab-findings.jsonl"))
    ap.add_argument("--ad", type=Path, default=Path("/var/log/soclab-ad-findings.jsonl"))
    ap.add_argument("--output", type=Path, default=Path("/var/log/soclab-alerts.jsonl"))
    ap.add_argument("--db", type=Path, default=Path("/var/lib/soclab-adapter/adapter.sqlite"))
    ap.add_argument("--poll", type=float, default=2.0)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--from-start", action="store_true",
                    help="Read historical findings on FIRST run with a NEW DB; for replay tests")
    ap.add_argument("--replay", action="store_true",
                    help="Tag emitted findings integration_test=true; use with --from-start")
    args = ap.parse_args()
    if args.poll <= 0:
        ap.error("--poll must be greater than zero")
    paths = [args.endpoint.resolve(), args.ad.resolve()]
    output = args.output.resolve()
    if output in paths or paths[0] == paths[1]:
        ap.error("Source files and destination must be distinct")
    os.umask(0o022)   # Allows Wazuh to read output created by this process.
    db = connect(args.db.resolve())
    print(f"Watching {paths[0]} and {paths[1]}; writing {output}", flush=True)
    try:
        while True:
            staged, sent = tick(db, paths, output, from_start=args.from_start, replay=args.replay)
            if staged or sent:
                print(f"Staged {staged}; sent {sent} findings", flush=True)
            if args.once:
                break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("Stopped", flush=True)
    finally:
        db.close()


if __name__ == "__main__":
    main()
