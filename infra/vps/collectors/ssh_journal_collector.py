from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

FAILED = re.compile(r"Failed (?:password|publickey) for (?:(invalid user) )?(\S+) from ([0-9a-fA-F:.]+) port (\d+)")
ACCEPTED = re.compile(r"Accepted (password|publickey) for (\S+) from ([0-9a-fA-F:.]+) port (\d+)")
INVALID = re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:.]+) port (\d+)")


def normalize_journal_record(record: dict[str, Any]) -> dict[str, Any] | None:
    message = str(record.get("MESSAGE") or "")
    timestamp = record.get("__REALTIME_TIMESTAMP")
    if timestamp:
        try:
            from datetime import datetime, timezone

            timestamp = datetime.fromtimestamp(int(timestamp) / 1_000_000, timezone.utc).isoformat().replace("+00:00", "Z")
        except (TypeError, ValueError):
            timestamp = None

    match = FAILED.search(message)
    if match:
        invalid, username, source_ip, source_port = match.groups()
        level = 8 if username == "root" or invalid else 6
        return _event(record, timestamp, message, "ssh_login", "failure", username, source_ip, source_port, level, credentials=True)
    match = ACCEPTED.search(message)
    if match:
        _method, username, source_ip, source_port = match.groups()
        return _event(record, timestamp, message, "ssh_login", "success", username, source_ip, source_port, 3)
    match = INVALID.search(message)
    if match:
        username, source_ip, source_port = match.groups()
        return _event(record, timestamp, message, "ssh_invalid_user", "failure", username, source_ip, source_port, 7, credentials=True)
    return None


def _event(record, timestamp, message, action, outcome, username, source_ip, source_port, level, credentials=False):
    basis = str(record.get("__CURSOR") or f"{timestamp}:{message}")
    value = {
        "id": f"ssh:{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:24]}",
        "timestamp": timestamp,
        "event": {"category": "authentication", "action": action, "outcome": outcome},
        "source": {"ip": source_ip, "port": int(source_port)},
        "user": {"name": username},
        "rule": {"id": f"{action}_{outcome}", "level": level},
        "message": message[:2000],
    }
    if credentials:
        value["credentials"] = [{"username": username}]
    return value


def collect(output_path: Path, cursor_path: Path) -> int:
    command = ["journalctl", "--no-pager", "--output=json", "--unit=ssh.service", "--lines=1000"]
    if cursor_path.is_file():
        cursor = cursor_path.read_text(encoding="utf-8").strip()
        if cursor:
            command.extend(["--after-cursor", cursor])
    else:
        command.extend(["--since=-15min"])
    result = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
    events, last_cursor = [], None
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        last_cursor = record.get("__CURSOR") or last_cursor
        event = normalize_journal_record(record)
        if event is not None:
            events.append(event)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if events:
        with output_path.open("a", encoding="utf-8", newline="\n") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        output_path.chmod(0o640)
    if last_cursor:
        cursor_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = cursor_path.with_suffix(".tmp")
        temporary.write_text(str(last_cursor), encoding="utf-8")
        os.replace(temporary, cursor_path)
    return len(events)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cursor", type=Path, required=True)
    args = parser.parse_args()
    collect(args.output, args.cursor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
