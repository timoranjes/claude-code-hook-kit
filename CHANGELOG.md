# Changelog

## 1.1.0

Marketplace compliance fixes. Hook behaviour is unchanged.

- Declare the supporter license key as a `sensitive` `userConfig` option (`license_key`) in `plugin.json`.
- `check_license.py` only validates a key passed as a CLI argument; it does not read environment variables, files or stored credentials.
- Add `.claude-plugin/icon.png` (512x512) and reference it from `plugin.json`.
- README: install by cloning the repo and running `python3 install.py`; remove download-and-run wording.

## 1.0.0

- Initial release: `guard_bash`, `guard_secrets`, `format_after_edit`, `session_log`, `hookkit_report`.
