# AI workflow contract

This repository is a Windows-only, local-first research workflow for data belonging to
the user who runs it. Treat process memory, database files, derived keys, contact names,
and query output as restricted personal data.

## Non-negotiable boundaries

- Confirm that the user is operating on their own account and machine before accessing
  a process or database directory.
- Never upload a database, memory dump, key file, local configuration, screenshot, or
  query result to any remote service.
- Never paste full local paths, account directory names, contact names, keys, or message
  content into an issue, commit, pull request, or chat response. Report only counts,
  exit codes, and redacted diagnostics.
- Do not terminate Weixin processes automatically. Ask the user to exit the client and
  later complete login themselves when step 1 requires it.
- Do not weaken or bypass the exact version and function-byte gates in
  `scripts/1_capture_launch.py`.
- Do not commit anything under `secrets/`, `exports/`, `Temp/`, or any real database or
  generated query output.

## Required agent sequence

1. Read `README.md`. Run the stdlib-only privacy gate before installing anything,
   then run the full offline release gate:

   ```bash
   python scripts/privacy_check.py
   python -m pip install -r requirements.txt
   python scripts/repo_check.py
   ```

2. Explore the machine read-only. Prefer a running process path for the installation
   and the client settings/config files for the data root. On PowerShell, useful probes
   include:

   ```powershell
   $wx = @(Get-CimInstance Win32_Process -Filter "Name='Weixin.exe'" -ErrorAction SilentlyContinue)
   if ($wx.Count -eq 1 -and $wx[0].ExecutablePath) {
     $env:WX_EXE = $wx[0].ExecutablePath
   }
   "Weixin process candidates: $($wx.Count)"  # print the count, not the path

   $roots = @(Get-ChildItem "$env:APPDATA\Tencent\xwechat\config" -Filter *.ini -ErrorAction SilentlyContinue |
     ForEach-Object { Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue })
   "Configured data roots: $($roots.Count)"    # ask the user to choose in Settings if ambiguous
   ```

   Do not quote the returned paths in a remote response. Ask the user to confirm the
   chosen installation and account directory if more than one candidate exists.

3. Set machine-specific values only in the current shell. Do not edit repository files:

   ```powershell
   $env:WX_EXE = '<confirmed Weixin.exe path>'
   $env:WX_DB_DIR = '<confirmed db_storage path>'
   # Optional: $env:WX_DIR, $env:WX_DLL, and $env:WX_SECRETS_DIR
   ```

4. Run the machine-readable preflight and resolve every `error` or `needs_input` item:

   ```bash
   python scripts/0_preflight.py --json
   ```

   Exit `0` means ready. Exit `2` means the user still needs to confirm configuration.
   Exit `1` means the environment or version profile is invalid.

5. If the exact Weixin.dll version differs from the verified profile, stop. Run the
   locator, review every high-scoring candidate, and set the three suggested variables
   in the same shell. A score is a lead, not proof. Do not adopt a tied candidate or a
   result without a complete `FileVersion`:

   ```bash
   python scripts/find_kdf_anchor.py "<confirmed Weixin.dll path>"
   ```

6. Ask the user to fully exit Weixin. Run step 1, then let the user perform login. Do not
   automate credentials or login UI:

   ```bash
   python scripts/1_capture_launch.py
   python scripts/2_extract_passphrase.py
   python scripts/3_derive_keys.py
   ```

   Validate downstream configuration without writing first. Only use `--apply` after
   the user confirms, and keep downstream installation pinned to the commit documented
   in `README.md`:

   ```bash
   python scripts/4_configure_wechat_cli.py
   python scripts/4_configure_wechat_cli.py --apply
   ```

7. Before any commit or push, run `python scripts/repo_check.py` again and inspect both
   staged and unstaged diffs. The privacy check must include Git history for a release.
   Also run Bandit and `pip-audit`, or confirm the corresponding GitHub Actions job is
   green.

## Validation claims

- `selftest_crypto.py` proves this repository's internal cryptographic round trip. It
  does not, by itself, prove compatibility with a new client build.
- Unit tests use synthetic pages and no personal data.
- CI covers offline behavior on Windows and Python 3.10, 3.12, and 3.14. It cannot test
  a real login or a vendor upgrade.
- Only claim live compatibility when the exact client version, breakpoint gate, capture,
  full-database derivation, and downstream read-only query were all tested successfully.

## Sensitive output handling

All workflow outputs default to the ignored `secrets/` directory. A custom path inside
the repository is accepted only under that ignored subtree. The workflow restricts the
sensitive directory itself, creates an empty sibling file, restricts its Windows DACL to
the current user, writes the data, atomically replaces the destination, and verifies the
final DACL. A protection failure must stop the workflow; do not fall back to `os.chmod`,
because it does not restrict Windows ACLs.
