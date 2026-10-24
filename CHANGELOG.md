# Changelog

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
