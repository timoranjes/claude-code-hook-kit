#!/usr/bin/env python3
"""PreToolUse hook for Read/Write/Edit/MultiEdit/NotebookEdit.

Blocks (1) writing credential-shaped strings into files and (2) touching sensitive files
such as .env, private keys and .git internals.
"""
import fnmatch
import sys

import _common as c

READ_TOOLS = {"Read"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

SENSITIVE_NAMES = [
    ("env-file", [".env", ".env.*"], [".env.example", ".env.sample", ".env.template"]),
    ("private-key-file", ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "*.p12", "*.pfx"], []),
    ("credentials-file", ["credentials.json", ".credentials.json", ".netrc", ".pgpass"], []),
]


def sensitive_path(path, writing):
    """Return (rule_id, message) if the path must not be touched, else None."""
    norm = path.replace("\\", "/")
    parts = norm.split("/")
    base = parts[-1]
    if writing and ".git" in parts[:-1]:
        return ("git-internals", "Do not edit files inside .git/. Use git commands instead.")
    for rule_id, patterns, exceptions in SENSITIVE_NAMES:
        if base in exceptions:
            continue
        if any(fnmatch.fnmatch(base, p) for p in patterns):
            return (rule_id, "'%s' holds secrets. Use a .env.example file with placeholder values." % base)
    return None


def _texts(tool_input):
    for key in ("content", "new_string", "new_source"):
        if isinstance(tool_input.get(key), str):
            yield tool_input[key]
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
            yield edit["new_string"]


def check_event(event, cfg):
    tool = event.get("tool_name")
    tin = event.get("tool_input") or {}
    disabled = set(cfg.get("disabled_rules", []))
    path = tin.get("file_path") or tin.get("notebook_path") or ""
    if path and (tool in READ_TOOLS or tool in WRITE_TOOLS):
        hit = sensitive_path(path, writing=tool in WRITE_TOOLS)
        if hit and hit[0] not in disabled:
            return hit
    if tool in WRITE_TOOLS:
        for text in _texts(tin):
            found = c.find_secrets(text, disabled)
            if found:
                rule_id, masked = found[0]
                return (rule_id, "Content contains what looks like a secret (%s). Read it from an environment "
                                 "variable instead of hardcoding it." % masked)
    return None


def main():
    event = c.read_event()
    root = c.project_dir(event)
    cfg = c.load_config(root)
    hit = check_event(event, cfg)
    if not hit:
        return 0
    tin = event.get("tool_input") or {}
    c.audit(root, cfg, event, "blocked", hook="guard_secrets", rule=hit[0], tool=event.get("tool_name"),
            path=tin.get("file_path") or tin.get("notebook_path") or "")
    return c.deny(hit[0], hit[1])


if __name__ == "__main__":
    sys.exit(main())
