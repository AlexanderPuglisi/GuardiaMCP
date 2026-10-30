# Changelog

## 0.5.3 — 30 October 2026

Last step of the look-alike pass: the same check now also covers the command a server runs. One new
scanner rule, with a malicious and a harmless test case; the full suite stays green. No network, no
runtime dependency.

**Scanner**
- New rule **G04-008**: a server whose `command` (the program it launches) hides Latin letters
  behind look-alikes from another alphabet — for example a Cyrillic «о» in `nоde` — is now flagged,
  with the name it reads as in plain letters. Together with G04-006 (tools) and G04-007 (server
  names), Guardia now checks every identifier a person reads in an MCP config for homoglyph
  impersonation.

## 0.5.2 — 30 October 2026

Follow-up to the look-alike rule: the same purple-team check now covers server names too. One new
scanner rule, with a malicious and a harmless test case; the full suite stays green. No network, no
runtime dependency.

**Scanner**
- New rule **G04-007**: a server configured under a name that hides Latin letters behind look-alikes
  from another alphabet — for example a Cyrillic «і» in `gіthub` — is now flagged, with the name it
  reads as in plain letters. This catches a server that impersonates one you trust in your MCP
  config, the companion to the tool-name check (G04-006) added in 0.5.1.

## 0.5.1 — 30 October 2026

A small hardening pass from a purple-team look at how a tool presents its name. One new scanner
rule, with a malicious and a harmless test case; the full suite stays green. No network, no runtime
dependency.

**Scanner**
- New rule **G04-006**: a tool or skill whose name hides Latin letters behind look-alikes from
  another alphabet — for example a Cyrillic «а» in `Reаd` — is now flagged, with the name it reads
  as in plain letters. When that plain-letter name is a built-in client tool, the finding is raised
  to critical: a homoglyph the exact-match check (G04-004) could never see. The same check runs in
  the real-time Shield, so a look-alike tool is hidden there as well.

## 0.5.0 — 29 October 2026

A second hardening pass, most of it from a fresh adversarial review (red-team) of the real-time
Shield. Two more ways around the result checks closed, each with a regression test; the full
suite stays green. No network, no runtime dependency.

**Shield**
- The result checks now cover `prompts/get` and `resources/read`, not only `tools/call`. A prompt
  or a resource is just as much server-controlled text that reaches the model, so a hidden
  instruction there is now caught the same way (before, only tool results were scanned for it).
- The secret and prompt-injection scan no longer stops after a fixed number of fields. A result
  padded with thousands of tiny items — enough to push the real payload past the old limit so it
  was never looked at — is now scanned in full. When a result genuinely is too large or too deeply
  nested to inspect completely, the Shield treats it cautiously (secrets redacted, the result
  flagged) instead of letting it through unchecked. This is a fail-closed change: when in doubt, it
  protects rather than passes.
- Secrets and injections hidden past the old depth or after a very long filler string are scanned
  (full-depth, untruncated), and a tool whose name is built at runtime in JavaScript is still
  analyzed from its description.

**App**
- Small inline help marks (ⓘ) on the overview explain the terms that trip up a first-time user:
  severity, the baseline, the ledger and analysis coverage. Hover or focus to read them.

## 0.4.0 — 29 October 2026

A hardening pass driven by an independent adversarial review (red-team) of the whole tool.
Three real weaknesses closed, each with a regression test; the full suite stays green.

**Shield**
- The message walker now inspects dictionary **keys**, not only values: a secret, a
  prompt-injection or a canary hidden in a JSON key is caught (it slipped through before).
- The canary has its own full-depth, untruncated scan, so a decoy buried in deep nesting or
  placed after a long filler string is still detected. Secret redaction now rewrites matching
  keys too.

**Backup**
- `guardia backup extract` opens the archive as uncompressed only, closing a decompression-bomb
  path where a tiny file could expand to fill the disk.

**Scanner**
- A path or URL hidden in an environment variable with a "secret-looking" name (for example
  `API_KEY=~/.ssh/id_rsa`) is no longer skipped: it is scanned like any other value.

**Legal**
- A plain-language disclaimer in [SECURITY.md](SECURITY.md): no warranty, modified copies are not
  official, and no liability — alongside the Apache 2.0 terms.

More hardening (ledger anchor, further scanner evasions, a self-integrity check, in-app help
tooltips) is planned for the next release.

## 0.3.0 — 28 October 2026

Two new built-in defenses, from the INFINITY-SAND doctrine ([INFINITY-SAND.md](INFINITY-SAND.md)).

**Canary (decoy)**
- `guardia canary create` makes a trap secret with a recognizable prefix; `--file` also plants it in
  a tempting fake secrets file. If any MCP server ever reads the bait and sends it back, the Shield
  sees it in the traffic, blocks the message and records it in the ledger with the `canary` label —
  whether it shows up in a server's reply or in a call heading out.
- `guardia canary list` and `guardia canary remove` manage them. The list of canaries is stored
  encrypted with DPAPI, like the ledger key.

**Encrypted rotating backups**
- `guardia backup create` makes an encrypted (DPAPI) snapshot of the ledger, approved rules and
  canaries, keeps the latest ones and deletes the old ones (`--keep`, default 10). Copy the file to
  a USB stick or another computer for a copy off this PC. `guardia backup extract <file> <folder>`
  restores it into a folder you choose, never over the live data.
- The safety copies made before a configuration edit are untouched and stay in clear text, so you
  can always restore a configuration by hand.

Both commands work in Italian too (`esca`, `copia`). 25 new automated tests; the full suite stays
green. Still no network and no runtime dependency.

## 0.2.3 — 24 October 2026

- **Fixed**: the animated glowing border never appeared with the window maximized (how the app
  opens since 0.2.2), and otherwise it was a 1-pixel line. It is now a soft red halo with two
  gentle lights that travel slowly along the edge, full screen or not, and in the confirmation
  window too. *Settings → Animated glowing border* turns it off; with Windows animations off the
  lights stay still.

## 0.2.2 — 24 October 2026

A careful pass on everything. Four separate reviews (scanner, Shield and command line, app,
documentation) reported 74 problems: 73 are fixed, the last one is a known limit written in
[SECURITY.md](SECURITY.md). Details and how it was checked: [TESTING.md](TESTING.md).

**App**
- Opens full screen and remembers its size and position; window buttons like every Windows app.
- A one-sentence verdict at the top: all clear, nothing installed, or what to fix first.
- Confirmations inside the app, clearer empty pages, nothing left in the old language after
  switching.
- **Create the example rules** opens the editor with the example and saves nothing until **Save and
  approve**.
- **Relink to this Guardia**: protected servers keep working after you move Guardia's folder.
- Broken configuration files are explained in plain words (for example "a comma is missing at
  line 3", or "in Windows paths write `\\`").
- The confirmation window shows the details of the request straight away, with the fields that
  triggered the rule first, and blocks after 45 seconds.

**Scanner**
- Far fewer false alarms: secret detection by whole words (`GIT_AUTHOR_NAME`, `--auth-mode` and
  file paths are no longer "secrets"), ordinary skill and tool texts, interpreter options, browser
  executables, CA certificates, `--env-file`, official package registries, proxies.
- Finds more: paths with spaces, project-relative paths and `${workspaceFolder}`, servers installed
  globally with npm, uv or pipx, `python -m` modules, Gemini CLI extensions, `CODEX_HOME` and
  `CLAUDE_CONFIG_DIR`, Codex headers and bearer tokens, passwords inside connection URLs.
- Never stops on malformed text: a problem with one server marks only that server as incomplete.
- An unreadable configuration file now makes the analysis incomplete instead of passing in silence.
- Network shares, WSL paths and network drives found in configurations are never opened
  automatically.
- New rules G12-008 and G12-009: an entry started through a `guardia` program that is not this
  installation, or through a Shield program that no longer exists.

**Shield**
- No more crash when the server closes first; the server's exit code is kept; Ctrl+C stops it.
- On Windows the server and every program it starts end together.
- Rate limits count only calls and never block a result.
- A request cancelled by the AI app is not carried out, and its confirmation window closes.
- Arguments with `&` or `|` reach `.cmd` launchers such as `npx` intact.
- Windows short paths (`PROGRA~1`) can no longer slip past path rules.
- Tools hidden by newly approved rules cannot be called any more, even from an old list.
- Fewer false password alerts; rules errors with the right line, in the language of your file.
- Protecting servers: a read-only file no longer stops the others, removing protection works even
  after you edited the entry, servers with the same name in different apps keep separate tool
  memories, and the Codex snippet is in TOML.

**Command line**
- Help fully translated, with readable placeholders and options in your language.
- `--nome` works everywhere; `--last` must be a positive number.
- Exit code 3 on unexpected errors, 2 when the output file cannot be written.

**Package and guides**
- Built without development tools; the zip also contains `CONTRIBUTING.md` and the images the
  README shows.
- Guides rewritten: download check that prints `True`, update, uninstall, and a table of common
  problems.

## 0.2.1 — 24 October 2026

- **Fixed**: the Windows executables did not start when the zip was downloaded from the Internet
  (`Failed to resolve Python.Runtime.Loader.Initialize`). Each program now ships a `.exe.config` that
  lets .NET load the libraries in its own folder. See [SECURITY.md](SECURITY.md).
- Step-by-step guide with screenshots: [docs/GUIDA.md](docs/GUIDA.md) (Italiano) and
  [docs/GUIDE.md](docs/GUIDE.md) (English).

## 0.2.0 — 23 October 2026

- First public release: static scanner (v1), real-time Shield (v2), tamper-evident ledger, desktop
  app and command line in Italian and English. See [TESTING.md](TESTING.md).
