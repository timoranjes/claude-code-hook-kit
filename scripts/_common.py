"""Shared helpers for the Hook Kit scripts. Standard library only."""
import json
import os
import re
import sys
import time
from pathlib import Path

DEFAULT_CONFIG = {
    "disabled_rules": [],
    "allow_commands": [],
    "extra_blocked_patterns": [],
    "log_dir": ".claude/hookkit-logs",
    "format_enabled": True,
    "format_timeout_seconds": 20,
}

# (rule id, compiled pattern). Patterns are deliberately specific to keep false positives low.
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("live-secret-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "hardcoded-credential",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b["']?\s*[:=]\s*["']([A-Za-z0-9/+_\-.]{20,})["']"""
        ),
    ),
]

PLACEHOLDER_HINTS = ("example", "your", "xxxx", "changeme", "placeholder", "dummy", "sample", "redacted", "<", "${")


def is_placeholder(value):
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS) or len(set(low)) <= 3


def mask(value):
    return value[:4] + "***" if len(value) > 4 else "***"


def find_secrets(text, disabled=()):
    """Return a list of (rule_id, masked_match) found in text."""
    hits = []
    for rule_id, rx in SECRET_PATTERNS:
        if rule_id in disabled:
            continue
        for m in rx.finditer(text or ""):
            value = m.group(1) if m.groups() else m.group(0)
            if rule_id == "hardcoded-credential" and is_placeholder(value):
                continue
            hits.append((rule_id, mask(value)))
    return hits


def redact(text):
    """Replace anything secret-shaped with a masked form (used before logging)."""
    for rule_id, rx in SECRET_PATTERNS:
        def sub(m, rule_id=rule_id):
            value = m.group(1) if m.groups() else m.group(0)
            if rule_id == "hardcoded-credential" and is_placeholder(value):
                return m.group(0)
            return m.group(0).replace(value, mask(value))
        text = rx.sub(sub, text)
    return text


def read_event(stream=None):
    stream = stream or sys.stdin
    try:
        data = json.loads(stream.read() or "{}")
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def project_dir(event=None):
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or (event or {}).get("cwd") or os.getcwd())


def load_config(root):
    cfg = dict(DEFAULT_CONFIG)
    path = Path(root) / ".claude" / "hookkit.json"
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            cfg.update(loaded)
    except (OSError, ValueError):
        pass
    return cfg


def audit(root, cfg, event, kind, **fields):
    """Append one JSON line to the session log. Never raises."""
    try:
        sid = re.sub(r"[^\w-]", "_", str(event.get("session_id") or "no-session"))[:64]
        log_dir = Path(root) / cfg["log_dir"]
        log_dir.mkdir(parents=True, exist_ok=True)
        gi = log_dir / ".gitignore"
        if not gi.exists():
            gi.write_text("*\n", encoding="utf-8")
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind}
        record.update(fields)
        with open(log_dir / (sid + ".jsonl"), "a", encoding="utf-8") as fh:
            fh.write(redact(json.dumps(record, ensure_ascii=False)) + "\n")
    except Exception:
        pass


def deny(rule_id, message):
    """Exit-code-2 convention: stderr is fed back to the model and the tool call is blocked."""
    sys.stderr.write("[hookkit:%s] Blocked. %s\n" % (rule_id, message))
    return 2
