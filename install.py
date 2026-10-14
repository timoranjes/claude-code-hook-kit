#!/usr/bin/env python3
"""Install (or remove) the Hook Kit in a project.

    python3 install.py [TARGET_DIR] [--dry-run] [--uninstall]

Copies kit/hooks/*.py to TARGET/.claude/hooks/ and merges hook entries into
TARGET/.claude/settings.json. Safe to run repeatedly. Existing settings are preserved
and backed up to settings.json.bak before the first change.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

KIT = Path(__file__).resolve().parent / "kit"
HOOK_FILES = ["_common.py", "guard_bash.py", "guard_secrets.py", "format_after_edit.py",
              "session_log.py", "hookkit_report.py"]
MARKER = ".claude/hooks/"

# (event, matcher, script)
ENTRIES = [
    ("PreToolUse", "Bash", "guard_bash.py"),
    ("PreToolUse", "Read|Write|Edit|MultiEdit|NotebookEdit", "guard_secrets.py"),
    ("PostToolUse", "Write|Edit|MultiEdit", "format_after_edit.py"),
    ("PostToolUse", "*", "session_log.py"),
    ("Stop", "*", "session_log.py"),
]


def command_for(script):
    return 'python3 "$CLAUDE_PROJECT_DIR/%s%s"' % (MARKER, script)


def _is_kit_command(cmd):
    return isinstance(cmd, str) and MARKER in cmd and any(cmd.rstrip('"').endswith(f) for f in HOOK_FILES)


def strip_kit(settings):
    """Return settings with every Hook Kit entry removed (other hooks untouched)."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return settings
    for event in list(hooks):
        groups = []
        for group in hooks[event]:
            kept = [h for h in group.get("hooks", []) if not _is_kit_command(h.get("command"))]
            if kept:
                groups.append(dict(group, hooks=kept))
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if not hooks:
        del settings["hooks"]
    return settings


def merge_settings(settings):
    settings = strip_kit(settings)
    hooks = settings.setdefault("hooks", {})
    for event, matcher, script in ENTRIES:
        hooks.setdefault(event, []).append(
            {"matcher": matcher, "hooks": [{"type": "command", "command": command_for(script)}]})
    return settings


def run(target, dry_run=False, uninstall=False, out=print):
    claude = target / ".claude"
    settings_path = claude / "settings.json"
    settings = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            out("ERROR: %s is not valid JSON (%s). Fix it and re-run; nothing was changed." % (settings_path, exc))
            return 1
    new = strip_kit(settings) if uninstall else merge_settings(settings)
    verb = "Removing" if uninstall else "Installing"
    out("%s Hook Kit in %s%s" % (verb, target, " (dry run)" if dry_run else ""))
    if dry_run:
        out(json.dumps(new, indent=2))
        return 0
    claude.mkdir(exist_ok=True)
    hooks_dir = claude / "hooks"
    if uninstall:
        for name in HOOK_FILES:
            (hooks_dir / name).unlink(missing_ok=True)
        pycache = hooks_dir / "__pycache__"
        if pycache.exists():
            shutil.rmtree(pycache)
        if hooks_dir.exists() and not any(hooks_dir.iterdir()):
            hooks_dir.rmdir()
    else:
        hooks_dir.mkdir(exist_ok=True)
        for name in HOOK_FILES:
            shutil.copy2(KIT / "hooks" / name, hooks_dir / name)
        cfg = claude / "hookkit.json"
        if not cfg.exists():
            shutil.copy2(KIT / "hookkit.json", cfg)
            out("  created .claude/hookkit.json")
    if settings_path.exists() and not (claude / "settings.json.bak").exists():
        shutil.copy2(settings_path, claude / "settings.json.bak")
    settings_path.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
    out("  wrote .claude/settings.json (%d hook entries)" % (0 if uninstall else len(ENTRIES)))
    out("Done." if uninstall else "Done. Restart Claude Code (or run /hooks) to load the hooks.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Install the Claude Code Hook Kit into a project.")
    ap.add_argument("target", nargs="?", default=".", help="project directory (default: current)")
    ap.add_argument("--dry-run", action="store_true", help="print the resulting settings.json, change nothing")
    ap.add_argument("--uninstall", action="store_true", help="remove the kit's hooks and scripts")
    args = ap.parse_args(argv)
    target = Path(args.target).resolve()
    if not target.is_dir():
        print("ERROR: %s is not a directory" % target)
        return 2
    return run(target, args.dry_run, args.uninstall)


if __name__ == "__main__":
    sys.exit(main())
