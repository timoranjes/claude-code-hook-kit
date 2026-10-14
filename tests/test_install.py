import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install  # noqa: E402


class InstallTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.proj = Path(self._tmp.name)
        self.settings = self.proj / ".claude" / "settings.json"
        self.log = []

    def tearDown(self):
        self._tmp.cleanup()

    def run_install(self, **kw):
        return install.run(self.proj, out=self.log.append, **kw)

    def load(self):
        return json.loads(self.settings.read_text())

    def test_fresh_install(self):
        self.assertEqual(self.run_install(), 0)
        for name in install.HOOK_FILES:
            self.assertTrue((self.proj / ".claude/hooks" / name).is_file(), name)
        self.assertTrue((self.proj / ".claude/hookkit.json").is_file())
        hooks = self.load()["hooks"]
        self.assertEqual(sorted(hooks), ["PostToolUse", "PreToolUse", "Stop"])
        self.assertEqual(len(hooks["PreToolUse"]), 2)

    def test_idempotent_and_preserves_other_settings(self):
        self.settings.parent.mkdir()
        other = {"type": "command", "command": "echo mine"}
        self.settings.write_text(json.dumps({
            "permissions": {"allow": ["Bash(ls)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [other]}]}}))
        self.run_install()
        first = self.load()
        self.run_install()
        self.assertEqual(self.load(), first)
        self.assertEqual(first["permissions"], {"allow": ["Bash(ls)"]})
        self.assertIn(other, [h for g in first["hooks"]["PreToolUse"] for h in g["hooks"]])
        self.assertTrue((self.proj / ".claude/settings.json.bak").exists())

    def test_uninstall_restores(self):
        self.settings.parent.mkdir()
        original = {"permissions": {"deny": ["Bash(rm:*)"]}}
        self.settings.write_text(json.dumps(original))
        self.run_install()
        self.run_install(uninstall=True)
        self.assertEqual(self.load(), original)
        self.assertFalse((self.proj / ".claude/hooks").exists())

    def test_dry_run_changes_nothing(self):
        self.assertEqual(self.run_install(dry_run=True), 0)
        self.assertFalse((self.proj / ".claude").exists())

    def test_invalid_json_aborts(self):
        self.settings.parent.mkdir()
        self.settings.write_text("{oops")
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.settings.read_text(), "{oops")
        self.assertFalse((self.proj / ".claude/hooks").exists())

    def test_installed_commands_point_at_real_files(self):
        self.run_install()
        for groups in self.load()["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    script = h["command"].split("/")[-1].rstrip('"')
                    self.assertTrue((self.proj / ".claude/hooks" / script).is_file(), script)


if __name__ == "__main__":
    unittest.main()
