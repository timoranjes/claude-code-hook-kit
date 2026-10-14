#!/usr/bin/env python3
"""60-second buyer smoke test: install into a throwaway project and exercise every hook.

    python3 smoke_test.py
"""
import json
import os
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILED = []


def check(label, ok, detail=""):
    print("  [%s] %s" % ("ok" if ok else "FAIL", label))
    if not ok:
        FAILED.append(label)
        if detail:
            print("        " + detail)


def hook(proj, script, event):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=str(proj))
    return subprocess.run([sys.executable, str(proj / ".claude/hooks" / script)], input=json.dumps(event),
                          capture_output=True, text=True, env=env, timeout=30)


def main():
    if sys.version_info < (3, 8):
        print("Python 3.8+ required")
        return 1
    print("Hook Kit smoke test")
    for f in sorted((HERE / "kit/hooks").glob("*.py")) + [HERE / "install.py"]:
        py_compile.compile(str(f), cfile=str(Path(tempfile.mkdtemp()) / "x.pyc"), doraise=True)
    check("all scripts compile", True)
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp)
        r = subprocess.run([sys.executable, str(HERE / "install.py"), str(proj)], capture_output=True, text=True)
        check("installer runs", r.returncode == 0, r.stdout + r.stderr)
        settings = json.loads((proj / ".claude/settings.json").read_text())
        check("settings.json has 5 hook entries", sum(len(g) for g in settings["hooks"].values()) == 5)

        r = hook(proj, "guard_bash.py", {"tool_name": "Bash", "tool_input": {"command": "git push --force"}, "session_id": "smoke"})
        check("force push is blocked (exit 2)", r.returncode == 2 and "git-force-push" in r.stderr, r.stderr)
        r = hook(proj, "guard_bash.py", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "session_id": "smoke"})
        check("ls is allowed (exit 0)", r.returncode == 0)
        fake = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
        r = hook(proj, "guard_secrets.py", {"tool_name": "Write", "session_id": "smoke",
                                           "tool_input": {"file_path": "a.py", "content": "k = '%s'" % fake}})
        check("hardcoded key is blocked (exit 2)", r.returncode == 2 and fake not in r.stderr, r.stderr)
        r = hook(proj, "guard_secrets.py", {"tool_name": "Read", "tool_input": {"file_path": str(proj / ".env")}})
        check(".env read is blocked (exit 2)", r.returncode == 2)
        r = hook(proj, "session_log.py", {"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "smoke",
                                         "tool_input": {"command": "ls"}})
        check("session log written", r.returncode == 0 and (proj / ".claude/hookkit-logs/smoke.jsonl").exists())
        r = subprocess.run([sys.executable, str(proj / ".claude/hooks/hookkit_report.py"),
                            str(proj / ".claude/hookkit-logs")], capture_output=True, text=True)
        check("report summarises log", r.returncode == 0 and "Blocked: 3" in r.stdout, r.stdout + r.stderr)
        print()
        print(r.stdout.rstrip())
        r = subprocess.run([sys.executable, str(HERE / "install.py"), str(proj), "--uninstall"], capture_output=True, text=True)
        check("uninstall is clean", r.returncode == 0 and not (proj / ".claude/hooks").exists())
    print()
    print("SMOKE TEST FAILED: %s" % ", ".join(FAILED) if FAILED else "SMOKE TEST PASSED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
