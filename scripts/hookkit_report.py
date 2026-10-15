#!/usr/bin/env python3
"""Summarise Hook Kit logs.

Usage: python3 .claude/hooks/hookkit_report.py [log_file_or_dir]
Default: .claude/hookkit-logs in the current directory.
"""
import collections
import json
import sys
from pathlib import Path


def load(path):
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    records = []
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return len(files), records


def render(sessions, records):
    tools = collections.Counter(r.get("tool") for r in records if r.get("kind") == "tool")
    blocked = collections.Counter(r.get("rule") for r in records if r.get("kind") == "blocked")
    fmt = collections.Counter(r.get("tool") for r in records if r.get("kind") == "formatted")
    failed = sum(1 for r in records if r.get("kind") == "tool" and r.get("failed"))
    lines = ["Sessions: %d   Records: %d" % (sessions, len(records)), "Tool calls: %d (%d failed)" % (sum(tools.values()), failed)]
    for name, n in tools.most_common():
        lines.append("  %-14s %d" % (name, n))
    lines.append("Blocked: %d" % sum(blocked.values()))
    for rule, n in blocked.most_common():
        lines.append("  %-22s %d" % (rule, n))
    lines.append("Files formatted: %d" % sum(fmt.values()))
    for name, n in fmt.most_common():
        lines.append("  %-14s %d" % (name, n))
    return "\n".join(lines)


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else Path(".claude/hookkit-logs")
    if not path.exists():
        sys.stderr.write("No logs found at %s\n" % path)
        return 1
    print(render(*load(path)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
