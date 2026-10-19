#!/usr/bin/env python3
"""Conservative, read-only portfolio publication preflight. Not a secret scanner guarantee."""
from pathlib import Path
import os
import re
import sys

root = Path(__file__).resolve().parent.parent
excluded_dirs = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', 'state', 'evidence', 'secrets', 'private', 'credentials'}
forbidden_suffixes = {'.jsonl', '.sqlite', '.sqlite3', '.db', '.evtx', '.pcap', '.pcapng', '.pem', '.key', '.pfx', '.p12', '.vdi', '.vmdk', '.iso'}
checks = [
    ('possible assignment of secret', re.compile(r'(?i)\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|private[_-]?key)\b\s*[:=]\s*["\'][^"\']{4,}["\']')),
    ('possible GitHub token', re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{15,}\b')),
    ('private key header', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ('AWS-style key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
]
issues=[]; files=0
for directory, dirs, names in os.walk(root):
    dirs[:] = [d for d in dirs if d not in excluded_dirs]
    for name in names:
        p=Path(directory)/name; rel=p.relative_to(root)
        if p.suffix.lower() in forbidden_suffixes or name in {'.env', 'client.keys'}:
            issues.append((str(rel), 0, 'potentially private artifact'))
            continue
        if p.stat().st_size > 2_000_000:
            issues.append((str(rel), 0, 'large file requires review'))
            continue
        try: content=p.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            if p.suffix.lower() not in {'.png','.jpg','.jpeg','.gif','.webp'}:
                issues.append((str(rel), 0, 'unreadable binary requires review'))
            continue
        files+=1
        for i,line in enumerate(content.splitlines(),1):
            if rel.as_posix()=='scripts/check_publish_ready.py':
                continue
            for label, rgx in checks:
                if rgx.search(line): issues.append((str(rel),i,label))
print(f'Publication check: {files} readable files examined.')
if issues:
    print('REVIEW REQUIRED (locations only; no secret values printed):')
    for f,line,why in issues: print(f'  {f}:{line} — {why}')
    print('Do not push until these findings are manually resolved.')
    sys.exit(1)
print('No findings from basic checks. Manual review is still REQUIRED before publishing.')
