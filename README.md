# Claude Code Hook Kit

**Buy (one-time, $19):** https://buy.polar.sh/polar_cl_vc6OdyNtVwQet8kOhVtT0V4oeFHShyOH6LIqe1WMoD5


Guardrail hooks for Claude Code, written in Python 3 (standard library only). No network
access, no API keys, no dependencies.

| Hook | Event | What it does |
|---|---|---|
| `guard_bash` | PreToolUse (Bash) | Blocks destructive shell commands |
| `guard_secrets` | PreToolUse (Read/Write/Edit/MultiEdit/NotebookEdit) | Blocks hardcoded secrets and access to `.env`, private keys, `.git/` internals |
| `format_after_edit` | PostToolUse (Write/Edit/MultiEdit) | Runs the formatter you already have installed |
| `session_log` | PostToolUse + Stop | Redacted JSONL log of every tool call and block |
| `hookkit_report` | CLI | Summarises the logs |

## Install (5 steps)

Requires Python 3.8+ (checked on 3.11) and Claude Code.

1. Unzip the kit anywhere: `unzip claude-code-hook-kit.zip -d hook-kit && cd hook-kit`
2. Run the smoke test: `python3 smoke_test.py` (about 2 seconds; it uses a temp directory)
3. Preview the change: `python3 install.py /path/to/your/project --dry-run`
4. Install: `python3 install.py /path/to/your/project`
5. Restart Claude Code in that project (or run `/hooks` to confirm five entries).

The installer copies scripts to `.claude/hooks/`, merges entries into `.claude/settings.json`
(your other settings and hooks are kept; a one-time `settings.json.bak` is written), and
creates `.claude/hookkit.json` if missing. Re-running is safe. Remove everything with
`python3 install.py /path/to/your/project --uninstall`.

## Smoke test output

```
$ python3 smoke_test.py
SMOKE_OUTPUT_PLACEHOLDER
```

## What gets blocked

Exit code 2 blocks the tool call, and the reason is returned to Claude so it can pick a
safer approach.

| Rule id | Example |
|---|---|
| `rm-system-path` | `rm -rf /`, `rm -rf ~`, `rm -rf /etc`, `rm -rf ..` |
| `rm-git-dir` | `rm -rf .git` |
| `git-force-push` | `git push --force`, `git push -f`, `git push origin +main` (`--force-with-lease` is allowed) |
| `git-discard` | `git reset --hard`, `git clean -fd`, `git checkout .` |
| `pipe-to-shell` | `curl ... \| sh`, `bash <(curl ...)` |
| `chmod-777` | `chmod -R 777 .` |
| `disk-write` | `dd of=/dev/sda`, `mkfs.*` |
| `fork-bomb` | `:(){ :\|:& };:` |
| `sql-drop` | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE` |
| `env-file-read` | `cat .env`, `grep X .env.local` (`.env.example` is fine) |
| `env-exfil` | `printenv \| curl ...` |
| `irreversible-publish` | `npm publish`, `twine upload`, `terraform destroy`, `kubectl delete ns` |
| `env-file`, `private-key-file`, `credentials-file`, `git-internals` | Read/Write on `.env*`, `id_rsa`, `*.pem`, `credentials.json`, `.git/*` |
| `aws-access-key`, `github-token`, `github-pat`, `slack-token`, `anthropic-key`, `openai-key`, `google-api-key`, `live-secret-key`, `private-key-block`, `jwt`, `hardcoded-credential` | Secret-shaped strings in file content being written |

Blocked secrets are never echoed in full: messages and logs show the first four characters
followed by `***`.

Matching is pattern-based, not a shell parser. A command that only mentions a dangerous
string inside quotes (for example `echo "git push --force"`) can be blocked too. Use
`allow_commands` below when that happens.

## Configure: `.claude/hookkit.json`

```json
{
  "disabled_rules": ["git-discard"],
  "allow_commands": ["^git push --force origin sandbox$"],
  "extra_blocked_patterns": [
    {"id": "no-prod-deploy", "pattern": "deploy\\.sh\\s+prod", "message": "Production deploys must be run by a human."}
  ],
  "log_dir": ".claude/hookkit-logs",
  "format_enabled": true,
  "format_timeout_seconds": 20
}
```

- `disabled_rules`: any rule id from the table above.
- `allow_commands`: regexes; a Bash command matching one skips all Bash rules.
- `extra_blocked_patterns`: your own regex rules with an id and a message.

## Formatter behaviour

`format_after_edit` picks the first formatter found per extension and never uses `npx`
or any download: `.py` ruff then black; `.js .jsx .ts .tsx .json .css .md .html .yml .yaml`
prettier (project `node_modules/.bin` first, then PATH); `.go` gofmt; `.rs` rustfmt;
`.sh` shfmt; `.tf` terraform fmt. Files outside the project, inside `node_modules`,
`.git`, `vendor`, `dist`, `build`, `.venv`, or missing on disk are skipped. A formatter
failure is logged and never blocks Claude.

## Logs and report

Logs are written to `.claude/hookkit-logs/<session_id>.jsonl` with a `.gitignore` that
excludes them from commits.

```
$ python3 .claude/hooks/hookkit_report.py
REPORT_OUTPUT_PLACEHOLDER
```

## Run the test suite

```
python3 -m unittest discover -s tests
```

## Notes

- Hooks run with your user permissions. Review the scripts (about 450 lines in total) before
  installing, as you would any code that runs on every tool call.
- Hook payload fields used: `tool_name`, `tool_input`, `tool_response`, `session_id`,
  `hook_event_name`, `cwd`. If a payload is unreadable, hooks exit 0 and do nothing.
- Scripts are called as `python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/<name>.py"`.

Licensed for use in your own projects and teams; see LICENSE.txt.

**Bundle (both tools, $29):** https://buy.polar.sh/polar_cl_APhmmzhYIlcAK8wpgidKSTaGC6lVRVLq1agZd3CPkaS
