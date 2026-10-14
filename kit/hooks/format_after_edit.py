#!/usr/bin/env python3
"""PostToolUse hook for Write/Edit/MultiEdit: format the edited file with a formatter that
is already installed. Nothing is ever downloaded. Always exits 0 so it can never block work.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import _common as c

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}
PRETTIER_EXTS = [".js", ".jsx", ".ts", ".tsx", ".json", ".css", ".md", ".html", ".yml", ".yaml"]

# extension -> ordered candidates; the first one found on this machine is used.
FORMATTERS = {
    ".py": [("ruff", ["format"]), ("black", ["-q"])],
    ".go": [("gofmt", ["-w"])],
    ".rs": [("rustfmt", [])],
    ".sh": [("shfmt", ["-w"])],
    ".tf": [("terraform", ["fmt"])],
}
for _ext in PRETTIER_EXTS:
    FORMATTERS[_ext] = [("prettier", ["--write"])]


def resolve(tool, root):
    local = Path(root) / "node_modules" / ".bin" / tool
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which(tool)


def plan(path, root):
    """Return the argv to run for this file, or None if nothing applies."""
    p = Path(path)
    try:
        rel = p.resolve().relative_to(Path(root).resolve())
    except ValueError:
        return None
    if SKIP_DIRS.intersection(rel.parts) or not p.is_file():
        return None
    for tool, args in FORMATTERS.get(p.suffix.lower(), []):
        exe = resolve(tool, root)
        if exe:
            return [exe] + args + [str(p)]
    return None


def main():
    event = c.read_event()
    root = c.project_dir(event)
    cfg = c.load_config(root)
    tin = event.get("tool_input") or {}
    path = tin.get("file_path") or tin.get("notebook_path")
    if not cfg.get("format_enabled", True) or not path:
        return 0
    argv = plan(path, root)
    if not argv:
        return 0
    try:
        proc = subprocess.run(argv, cwd=str(root), capture_output=True, text=True,
                              timeout=cfg.get("format_timeout_seconds", 20))
        if proc.returncode == 0:
            c.audit(root, cfg, event, "formatted", tool=Path(argv[0]).name, path=path)
        else:
            c.audit(root, cfg, event, "format_failed", tool=Path(argv[0]).name, path=path,
                    detail=(proc.stderr or proc.stdout)[:200])
    except (OSError, subprocess.SubprocessError):
        c.audit(root, cfg, event, "format_failed", tool=Path(argv[0]).name, path=path, detail="timeout or exec error")
    return 0


if __name__ == "__main__":
    sys.exit(main())
