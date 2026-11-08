# Changelog

## 0.5.8 — 8 November 2026

A visual release with a safety net under it. Before the report and the windows were redesigned,
new tests locked in every protection they must keep; then GuardiaMCP moved to its new graphite
identity.

**Look**
- The HTML report (`--format html`) is graphite with a steel accent: the shield mark and a
  "100% offline" badge in the header, severity colours kept apart from the brand colour (red
  critical, orange high, yellow medium), coloured summary cards with zero counts dimmed, a
  severity border on every server, framed "found" values and a +/– hint on each entry. It follows
  the system light theme on its own.
- The app and the Shield confirmation window are graphite with a steel accent, and the glow that
  circles the window border is now steel. Red now means only an alarm: problem and Shield
  counters, danger buttons, error text, the reasons in a Shield warning, critical findings. High
  findings are orange and medium ones yellow, as in the report.
- A new program icon: a steel-blue shield.

**Security**
- New tests lock in what the redesign must not weaken: hostile server names, arguments and tool
  descriptions reach the report only as text, never as markup; the report and both windows keep
  exactly their strict Content Security Policies (no network, fonts, frames or inline code); no
  stylesheet loads anything from outside. Nothing was loosened: the report still runs no scripts,
  and Windows system fonts are used instead of web fonts so nothing is ever fetched.

**Build**
- `uv.lock` had fallen out of step with the version since 0.5.4, which stopped the CI install step
  before any check ran. It is in sync again and CI is green.
- The guides and their screenshots show the new look.

## 0.5.7 — 2 November 2026

The last gap in the de-obfuscation started in 0.5.5. Folding look-alike letters caught an
instruction spelled in another alphabet, but not one broken up with invisible characters: a
zero-width space inside `instru<zero-width>ctions`, or a bidi control, keeps the sentence readable
while splitting the keyword the pattern looks for. The text now has those invisible format and
control characters removed before the content patterns run, so the keyword rejoins and the
instruction is matched. The raw text is still reported verbatim, so the hidden-character rule
(G01-001) keeps flagging the characters themselves.

**Scanner**
- Tool and skill text is stripped of invisible format/control characters (zero-width spaces, bidi
  controls, soft hyphens, and the like — ordinary whitespace is kept) before the content patterns
  run, on top of the look-alike fold from 0.5.5. A prompt injection or exfiltration instruction cut
  apart by invisible characters is now caught by its existing rule.
- New corpus case `zero_width_injection.py`: an injection split by a zero-width space, undetected as
  an instruction before this change and flagged afterwards (alongside G01-001 for the hidden
  character itself). The full suite stays green.

## 0.5.6 — 2 November 2026

More alphabets behind the look-alike check. Until now Guardia only knew the Latin letters that
Cyrillic and Greek borrow; an attacker could reach for Armenian or, worst of all, Cherokee — whose
alphabet is full of capitals that are near-perfect twins of Latin ones (`Ꭺ`→A, `Ꭼ`→E, `Ꮐ`→G). The
look-alike table now covers those two scripts as well, taken from the Unicode security confusables
data (UTS #39), so every check that reads a name through it gets the wider coverage at once.

**Scanner**
- The look-alike table gains 51 Armenian and Cherokee letters. This strengthens the name checks
  (G04-006 tools, G04-007 servers, G04-008 commands) and, since 0.5.5, the de-obfuscation of tool
  text before the content patterns run — all of them share the one table.
- New corpus case `cherokee_name.py`: a tool named with a Cherokee letter that reads as the built-in
  `Grep` (flagged critical, like any look-alike of a built-in tool). The full suite stays green.

## 0.5.5 — 2 November 2026

The look-alike work so far flagged a disguised *name*. This closes the matching hole in the other
direction: a disguised *instruction*. Guardia's content checks — prompt injection, shadowing,
secret and context exfiltration, sensitive-file access — matched the plain-letter phrasing, so an
attacker could slip the same instruction past them by spelling it with letters borrowed from another
alphabet (a Cyrillic «о» in "ignоre all previous instructions"). The text now runs through the same
look-alike fold before the patterns see it, so the instruction is matched as what it reads as. No
new rule, no new dependency; the existing rules simply stop being fooled by the disguise.

**Scanner**
- Tool and skill text fields are de-obfuscated before the content patterns run: look-alike letters
  are folded back to Latin (on top of the tag-character stripping that was already there). A prompt
  injection or exfiltration instruction hidden behind homoglyphs is now caught by its existing rule
  (for example **G02-001**), with the evidence shown as the plain phrase it decodes to.
- New corpus case `homoglyph_injection.py`: an injection written with Cyrillic look-alikes that goes
  undetected before this change and is flagged afterwards. The full suite stays green.

## 0.5.4 — 2 November 2026

A second look-alike pass, from the same purple-team angle. The homoglyph rules (G04-006…008) catch
letters borrowed from another alphabet; they do not catch a letter written in a disguised
presentation form — full-width, mathematical, a ligature — that reads as an ordinary letter but is a
different code point. NFKC folds every one of those back to plain ASCII, so Guardia now flags them
too, across the same three identifiers a person reads in an MCP config. Three new rules, each with a
malicious and a harmless test case; the full suite stays green. No network, no runtime dependency.

**Scanner**
- New rule **G04-009**: a tool or skill whose name writes its letters in a disguised form — for
  example the full-width «Ｒｅａｄ» or the mathematical «𝐑𝐞𝐚𝐝», both read as `Read` — is now flagged,
  with the name it reads as in plain letters. CRITICAL when that plain name is a built-in client
  tool.
- New rule **G04-010**: the same disguise in a server name.
- New rule **G04-011**: the same disguise in the `command` a server launches, so a config that looks
  like it runs a trusted program but hides a different string is caught.
- Together with the homoglyph rules from 0.5.1–0.5.3, Guardia now checks every identifier in an MCP
  config for both cross-alphabet and compatibility-form impersonation. The check is letter-only, so
  ordinary accented names (`café-notes`, `résumé_search`) and symbols like `™` stay clean.

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
