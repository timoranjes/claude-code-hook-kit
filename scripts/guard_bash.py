#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool: block destructive or irreversible shell commands.

Exit 0 = allow, exit 2 = block (reason on stderr is shown to the model).
"""
import re
import shlex
import sys

import _common as c

SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
SYSTEM_TARGETS = {
    "/", "~", "$HOME", "${HOME}", "..", ".",
    "/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/lib", "/home", "/root", "/opt",
}

RULES = [
    ("git-force-push",
     re.compile(r"\bgit\s+(?:-\S+\s+)*push\b[^;&|\n]*?(?:\s--force(?!-with-lease)\b|\s-[a-zA-Z]*f[a-zA-Z]*\b|\s\+\S+)"),
     "Force push can overwrite remote history. Use --force-with-lease on a feature branch, or ask the user."),
    ("git-discard",
     re.compile(r"\bgit\s+reset\s+[^;&|\n]*--hard\b|\bgit\s+clean\s+[^;&|\n]*-[a-zA-Z]*f|\bgit\s+checkout\s+(?:--\s+)?\.(?:\s|$)|\bgit\s+restore\s+[^;&|\n]*\s\.(?:\s|$)"),
     "This discards uncommitted work. Commit or stash first, or ask the user."),
    ("pipe-to-shell",
     re.compile(r"\b(?:curl|wget)\b[^\n;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)"),
     "Piping a download into a shell runs unreviewed code. Download the file, read it, then run it."),
    ("chmod-777",
     re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*0?777\b"),
     "World-writable permissions are rarely correct. Use a narrower mode such as 755 or 644."),
    ("disk-write",
     re.compile(r"\bdd\b[^\n;&|]*\bof=/dev/|\bmkfs(?:\.\w+)?\b|>\s*/dev/(?:sd|nvme|hd|vd)"),
     "Writing to block devices destroys data."),
    ("fork-bomb",
     re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:"),
     "Fork bomb pattern."),
    ("sql-drop",
     re.compile(r"(?i)\bdrop\s+(?:database|schema|table)\b|\btruncate\s+table\b"),
     "Destructive SQL. Run it yourself if intended."),
    ("env-file-read",
     re.compile(r"\b(?:cat|less|more|head|tail|bat|grep|rg|sed|awk|source)\b[^|;&\n]*\.env\b(?!\.(?:example|sample|template)\b)"),
     "Reading .env files would put secrets in the conversation. Read .env.example instead."),
    ("env-exfil",
     re.compile(r"\b(?:printenv|env)\b[^\n;&]*\|\s*(?:curl|nc|ncat|wget)\b"),
     "Piping the environment to a network tool leaks secrets."),
    ("irreversible-publish",
     re.compile(r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bterraform\s+(?:destroy|apply\s+[^\n;&|]*-auto-approve)|\bkubectl\s+delete\s+(?:ns|namespace)\b"),
     "Publishing or destroying infrastructure is irreversible. Ask the user to run it."),
]


def _tokens(segment):
    try:
        toks = shlex.split(segment)
    except ValueError:
        toks = segment.split()
    while toks and (toks[0] in ("sudo", "env", "command", "nohup", "time") or re.match(r"^\w+=", toks[0])):
        toks = toks[1:]
    return toks


def _normalise(target):
    if target.endswith("/*"):
        target = target[:-2]
    target = target.rstrip("/")
    return target or "/"


def _check_rm(command):
    for seg in SEGMENT_SPLIT.split(command):
        toks = _tokens(seg)
        if not toks or toks[0] != "rm":
            continue
        flags = [t for t in toks[1:] if t.startswith("-")]
        recursive = any(f == "--recursive" or (not f.startswith("--") and ("r" in f or "R" in f)) for f in flags)
        if not recursive:
            continue
        for t in toks[1:]:
            if t.startswith("-"):
                continue
            if _normalise(t) in SYSTEM_TARGETS:
                return ("rm-system-path", "Recursive delete of '%s' would destroy system or home data." % t)
            if _normalise(t) == ".git":
                return ("rm-git-dir", "Deleting .git removes all repository history.")
    return None


def check_command(command, cfg):
    """Return (rule_id, message) for the first matching rule, or None."""
    disabled = set(cfg.get("disabled_rules", []))
    for pat in cfg.get("allow_commands", []):
        if re.search(pat, command):
            return None
    hit = _check_rm(command)
    if hit and hit[0] not in disabled:
        return hit
    for rule_id, rx, message in RULES:
        if rule_id not in disabled and rx.search(command):
            return (rule_id, message)
    for extra in cfg.get("extra_blocked_patterns", []):
        if extra.get("id") not in disabled and re.search(extra["pattern"], command):
            return (extra["id"], extra.get("message", "Blocked by project rule."))
    return None


def main():
    event = c.read_event()
    if event.get("tool_name") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command") or ""
    root = c.project_dir(event)
    cfg = c.load_config(root)
    hit = check_command(command, cfg)
    if not hit:
        return 0
    c.audit(root, cfg, event, "blocked", hook="guard_bash", rule=hit[0], command=command[:300])
    return c.deny(hit[0], hit[1])


if __name__ == "__main__":
    sys.exit(main())
