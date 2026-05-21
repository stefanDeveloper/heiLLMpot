#!/usr/bin/env python3
"""Summarize honeybot JSONL logs into Markdown, JSON, and CSV artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def session_ref(data: dict[str, Any]) -> str:
    for key in ("session_ref", "session_id", "connection_id"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def field(data: dict[str, Any], key: str) -> str:
    value = data.get(key, "")
    return "" if value is None else str(value)


def load_events(path: Path) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    malformed = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(entry, dict):
                events.append(entry)
            else:
                malformed += 1
    return events, malformed


def normalize_event(entry: dict[str, Any], redact_passwords: bool) -> dict[str, str]:
    data = entry.get("data", {})
    if not isinstance(data, dict):
        data = {}

    password = field(data, "password")
    if redact_passwords and password:
        password = "<redacted>"

    return {
        "timestamp": str(entry.get("timestamp", "")),
        "protocol": str(entry.get("protocol", "")).lower(),
        "event_type": str(entry.get("event", "")).lower(),
        "client_ip": field(data, "client_ip"),
        "client_port": field(data, "client_port"),
        "session_ref": session_ref(data),
        "method": field(data, "method"),
        "path": field(data, "path"),
        "status_code": field(data, "status_code"),
        "username": field(data, "username"),
        "password": password,
        "user_agent": field(data, "user_agent"),
        "command": field(data, "command"),
        "site_id": field(data, "site_id"),
    }


def top(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count}
        for value, count in counter.most_common(limit)
        if value
    ]


def build_summary(rows: list[dict[str, str]], malformed: int, top_n: int) -> dict[str, Any]:
    protocol_counts = Counter(row["protocol"] for row in rows)
    event_counts = Counter(row["event_type"] for row in rows)
    ip_counts = Counter(row["client_ip"] for row in rows if row["client_ip"])
    path_counts = Counter(row["path"] for row in rows if row["path"])
    status_counts = Counter(row["status_code"] for row in rows if row["status_code"])
    ua_counts = Counter(row["user_agent"] for row in rows if row["user_agent"])
    command_counts = Counter(row["command"] for row in rows if row["command"])

    credential_counts: Counter[str] = Counter()
    for row in rows:
        if row["username"] or row["password"]:
            credential_counts[f"{row['username']}:{row['password']}"] += 1

    hourly_counts: Counter[str] = Counter()
    timestamps: list[datetime] = []
    sessions: dict[str, dict[str, Any]] = {}

    for row in rows:
        parsed = parse_ts(row["timestamp"])
        if parsed:
            timestamps.append(parsed)
            hourly_counts[parsed.strftime("%Y-%m-%d %H:00")] += 1

        ref = row["session_ref"]
        if not ref:
            continue
        current = sessions.setdefault(
            ref,
            {
                "session_ref": ref,
                "client_ip": row["client_ip"],
                "protocols": set(),
                "event_count": 0,
                "paths": Counter(),
                "commands": Counter(),
                "credentials": Counter(),
                "first_seen": parsed,
                "last_seen": parsed,
            },
        )
        current["event_count"] += 1
        if row["protocol"]:
            current["protocols"].add(row["protocol"])
        if row["path"]:
            current["paths"][row["path"]] += 1
        if row["command"]:
            current["commands"][row["command"]] += 1
        if row["username"] or row["password"]:
            current["credentials"][f"{row['username']}:{row['password']}"] += 1
        if parsed:
            if current["first_seen"] is None or parsed < current["first_seen"]:
                current["first_seen"] = parsed
            if current["last_seen"] is None or parsed > current["last_seen"]:
                current["last_seen"] = parsed

    session_rows = []
    for item in sessions.values():
        first_seen = item["first_seen"]
        last_seen = item["last_seen"]
        duration = ""
        if first_seen and last_seen:
            duration = f"{(last_seen - first_seen).total_seconds():.3f}"
        session_rows.append(
            {
                "session_ref": item["session_ref"],
                "client_ip": item["client_ip"],
                "protocols": ",".join(sorted(item["protocols"])),
                "event_count": item["event_count"],
                "first_seen": first_seen.isoformat() if first_seen else "",
                "last_seen": last_seen.isoformat() if last_seen else "",
                "duration_sec": duration,
                "top_paths": "; ".join(
                    f"{value} ({count})" for value, count in item["paths"].most_common(5)
                ),
                "commands": "; ".join(
                    f"{value} ({count})" for value, count in item["commands"].most_common(5)
                ),
                "credentials": "; ".join(
                    f"{value} ({count})" for value, count in item["credentials"].most_common(5)
                ),
            }
        )

    session_rows.sort(key=lambda item: item["event_count"], reverse=True)

    return {
        "total_events": len(rows),
        "malformed_lines": malformed,
        "first_seen": min(timestamps).isoformat() if timestamps else "",
        "last_seen": max(timestamps).isoformat() if timestamps else "",
        "unique_sessions": len(sessions),
        "unique_ips": len(ip_counts),
        "protocols": dict(protocol_counts),
        "event_types": dict(event_counts),
        "status_codes": dict(status_counts),
        "top_ips": top(ip_counts, top_n),
        "top_paths": top(path_counts, top_n),
        "top_credentials": top(credential_counts, top_n),
        "top_user_agents": top(ua_counts, top_n),
        "top_commands": top(command_counts, top_n),
        "events_by_hour": dict(sorted(hourly_counts.items())),
        "sessions": session_rows,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(items: list[dict[str, Any]], headers: tuple[str, str]) -> str:
    if not items:
        return "_No data._\n"
    lines = [f"| {headers[0]} | {headers[1]} |", "| --- | ---: |"]
    for item in items:
        lines.append(f"| `{item['value']}` | {item['count']} |")
    return "\n".join(lines) + "\n"


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Honeypot Analysis Summary",
        "",
        f"- Total events: {summary['total_events']}",
        f"- Malformed lines skipped: {summary['malformed_lines']}",
        f"- First seen: {summary['first_seen'] or 'n/a'}",
        f"- Last seen: {summary['last_seen'] or 'n/a'}",
        f"- Unique sessions: {summary['unique_sessions']}",
        f"- Unique client IPs: {summary['unique_ips']}",
        "",
        "## Protocols",
        markdown_table(
            [{"value": k, "count": v} for k, v in summary["protocols"].items()],
            ("Protocol", "Events"),
        ),
        "## Event Types",
        markdown_table(
            [{"value": k, "count": v} for k, v in summary["event_types"].items()],
            ("Event", "Count"),
        ),
        "## Top Client IPs",
        markdown_table(summary["top_ips"], ("IP", "Events")),
        "## Top Paths",
        markdown_table(summary["top_paths"], ("Path", "Hits")),
        "## Top Credentials",
        markdown_table(summary["top_credentials"], ("Username:Password", "Attempts")),
        "## Top User Agents",
        markdown_table(summary["top_user_agents"], ("User Agent", "Requests")),
        "## Top Commands",
        markdown_table(summary["top_commands"], ("Command", "Runs")),
        "",
        "CSV exports: `events.csv`, `sessions.csv`",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze honeybot JSONL logs without external dependencies."
    )
    parser.add_argument("--log-file", type=Path, default=Path("honeybot/honeypot.log"))
    parser.add_argument("--out", type=Path, default=Path("analysis/output"))
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--redact-passwords", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.log_file.exists():
        raise SystemExit(f"Log file not found: {args.log_file}")

    events, malformed = load_events(args.log_file)
    rows = [normalize_event(entry, args.redact_passwords) for entry in events]
    summary = build_summary(rows, malformed, args.top)

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(args.out / "events.csv", rows)
    write_csv(args.out / "sessions.csv", summary["sessions"])
    (args.out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    write_markdown(args.out / "summary.md", summary)

    print(f"Wrote analysis artifacts to {args.out}")
    print(f"Events: {summary['total_events']} | Sessions: {summary['unique_sessions']} | IPs: {summary['unique_ips']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
