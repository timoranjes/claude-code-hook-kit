#!/usr/bin/env python3
"""PostToolUse + Stop hook: append a redacted JSONL record of every tool call.

Logs live in <project>/.claude/hookkit-logs/<session_id>.jsonl (git-ignored automatically).
"""
import sys

import _common as c


def build_record(event):
    name = event.get("hook_event_name") or "unknown"
    if name == "Stop":
        return "stop", {}
    tin = event.get("tool_input") or {}
    resp = event.get("tool_response")
    failed = isinstance(resp, dict) and bool(resp.get("is_error") or resp.get("error"))
    summary = (tin.get("command") or tin.get("file_path") or tin.get("notebook_path")
               or tin.get("pattern") or tin.get("url") or "")
    return "tool", {"tool": event.get("tool_name"), "summary": str(summary)[:200], "failed": failed}


def main():
    event = c.read_event()
    root = c.project_dir(event)
    cfg = c.load_config(root)
    kind, fields = build_record(event)
    c.audit(root, cfg, event, kind, **fields)
    return 0


if __name__ == "__main__":
    sys.exit(main())
