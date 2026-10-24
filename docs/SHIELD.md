# The Guardia MCP Shield

**by Alexander Puglisi** · [Versione italiana](SCUDO.md)

The Shield is the part of Guardia that works **while** the AI is using MCP servers. The v1 scanner
reads files and tells you what is risky; the Shield sits between the messages and can **block,
hide or redact** them following rules you write.

> **Status: version 0.2.3.** Rules, built-in protections, the confirmation window, automatic
> client setup and the "Shield" view in the app. Tested with the official MCP Python SDK
> (protocols 2025-11-25 and 2026-07-28).

## How it works, in 30 seconds

```
AI app (client)  ⇄  guardia shield  ⇄  MCP server
                          │
                 rules file  +  ledger
```

**Proxy** — a program that sits between two others and passes messages from one to the other.
The Shield is a proxy: the client talks to the Shield, the Shield talks to the server.

For every message the Shield:

1. checks that it is a valid MCP message (otherwise it drops it);
2. looks at your rules and decides: allow, log, redact, ask or block;
3. writes the decision to the tamper-evident ledger;
4. forwards the message, or answers with an error that says which rule stopped it.

If something goes wrong (unapproved rules, ledger not writable, internal error) the Shield
**blocks instead of letting the message through**. This is called **fail-closed**: when in doubt,
the door stays shut.

## Running a server behind the Shield

```powershell
guardia shield --server github -- npx -y @modelcontextprotocol/server-github
```

Everything after `--` is the server command, exactly as you would write it in the client
configuration. Guardia's messages (active rules, blocks) go to the client's error log, never to
the MCP channel.

To protect a server in Claude Desktop, change its entry in `claude_desktop_config.json` from:

```json
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
```

to:

```json
{
  "command": "C:\\Users\\YOUR-NAME\\GuardiaMCP\\guardia.exe",
  "args": ["shield", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
}
```

The same pattern works for Claude Code, Cursor and VS Code, but **you do not need to do it by
hand**: Guardia does it for you.

### Connecting servers automatically

```powershell
guardia shield list
guardia shield enable --server github
guardia shield enable --server github --confirm
guardia shield disable --server github --confirm
guardia shield relink --all --confirm
```

- **list** shows every MCP server on the PC and, for each, whether it is protected by the Shield,
  whether it can be connected automatically, or why not.
- **enable** without `--confirm` only shows what it would do; with `--confirm` it saves a backup of
  the file in Guardia's `backup` folder, changes only that server's entry and records the original
  entry. `--all` connects every server that can be connected.
- **disable** restores the original entry. If you changed the entry after protecting it (for
  example a new key in `env`), it removes only the Shield and keeps your changes.
- **relink** is for when Guardia's folder was moved or renamed: protected servers would still look
  for the old `guardia.exe`. It points them to this copy of Guardia. In the app the button is
  **Relink to this Guardia**.
- When servers in different apps share a name (for example `filesystem` in Claude and in Cursor),
  Guardia gives each one its own Shield name, such as `filesystem (cursor)`, so that their tool
  memories stay separate.
- The same actions are in the **Shield** section of the app, with a confirmation before every change.

**Close the AI app** before connecting a server: some apps rewrite their own configuration file and
could erase the change. If Guardia notices that the file changed while it was working, it writes
nothing.

| Where the server lives | What Guardia does |
|---|---|
| Plain JSON file (Claude Desktop, Claude Code, Cursor, VS Code `mcp.json`, Windsurf, Gemini, Copilot) | Automatic connection |
| File with comments (for example VS Code `settings.json`) or TOML file (Codex) | Shows you the exact text to paste (in TOML for Codex), so your comments are not touched |
| Claude Desktop extensions, plugins, administrator-managed configurations | Cannot be connected: the apps manage them |
| Remote (HTTP) servers | Not protected by the Shield yet |

A connected server is still analyzed by the v1 scan with its **original command**: protection hides
nothing from the analysis. If an entry goes through a `guardia` program that is not this
installation, the scan reports it (rule G12-008); if Guardia's folder was moved and that program no
longer exists, it reports that the AI app cannot start the server (G12-009).

## Rules in five minutes

**From the app**, without a terminal: **Shield** section → **Create the example rules**: the
editor opens with the example, not saved yet → change the text → **Save and approve**. Guardia
checks the text before saving it: if something is wrong it shows the line and saves nothing.

**From the command line:**

```powershell
guardia shield rules example --save
guardia shield rules verify
guardia shield rules test --tool read_file --arguments '{"path": "~/.ssh/id_rsa"}'
guardia shield rules approve
guardia shield rules status
```

1. **example --save** creates the rules file with five rules that are useful for everyone.
   Until you approve it, protected servers are in **full lockdown** (the file is not signed yet):
   close the AI app while you edit.
2. Open the file with a text editor and adapt it.
3. **verify** checks the file and tells you line by line what is wrong, with a suggestion when
   you misspell a key.
4. **test** simulates a message and shows which decision **your rules** would take, without
   starting any server. The built-in protections are not simulated. In Windows PowerShell 5.1
   escape the inner quotes: `--arguments '{\"path\": \"~/.ssh/id_rsa\"}'` (PowerShell 7 accepts
   the form above).
5. **approve** checks the file, shows the differences from the last version and **signs** it.
   Running Shields use the new rules within one second.
6. **status** tells you whether the rules are active or the Shield is in full lockdown, and why.

The commands also exist in Italian: `guardia scudo regole verifica | approva | prova | esempio | stato`.
The example file is in English when your language is English (`--lang en`).

## The confirmation window

When a rule or a protection says `ask`, the Shield opens a small Guardia window, always on top,
that shows:

- which server wants to do what (tool or request);
- **why** it is asking (the rule or the protection);
- the request details, already open: first the fields that triggered the rule, each value cut at
  300 characters, with secrets already redacted;
- the **Block** button (selected by default, for safety) and **Allow**, plus the box "remember the
  choice for 10 minutes" for that tool;
- a countdown: **if you do not answer within 45 seconds, it blocks**. `Esc` and the close circle
  also block.

While it waits for your answer, the Shield keeps passing other messages. The window is a separate
Guardia process that talks to the Shield over a private channel: **the AI and the server cannot
answer on your behalf**. If the window cannot be shown, the request is blocked. Every answer goes
into the ledger. If the client cancels the request while the window is open (for example because
it stopped waiting), the window closes and the request is not carried out.

`ask` applies to **calls** and **server requests**. On results and lists asking makes no sense (the
action already happened or has not been requested yet): there it works like `log`.

## Built-in protections

The Shield protects you even **without any rule written by you**. These protections apply in
real time the v1 rules that check tool descriptions, schemas and server instructions.

| Protection | What it does | Default | Values |
|---|---|---|---|
| `approved_tools` | The first time it sees a server it stores its tools. If a tool later **changes** (rug pull) or **suddenly appears**, it is hidden from the AI until you approve it | `true` | `true`, `false` |
| `analysis` | Checks the description and schema of every listed tool and the server instructions: hides tools and removes instructions with findings at that level or above | `"high"` | `"critical"`, `"high"`, `"medium"`, `"off"` |
| `results` | Looks for prompt injection and hidden instructions in tool results | `"warn"` | `"warn"`, `"block"`, `"off"` |
| `outgoing_secrets` | A secret (key, token) in the arguments of a call | `"ask"` | `"ask"`, `"block"`, `"log"`, `"off"` |
| `result_secrets` | Secrets in results: replaced with `[REDACTED]` | `"redact"` | `"redact"`, `"off"` |
| `credential_requests` | A server asks you, in a form (elicitation), for passwords, OTPs, PIN codes, keys, recovery phrases or card data | `"block"` | `"block"`, `"ask"`, `"log"`, `"off"` |

`warn` lets the result through but reports it in the ledger and in the client log.

**A hidden tool cannot be called either**: if the AI tries to use it (because it remembered it,
or because the client kept an old list in memory), the Shield blocks the call and explains why.
For the same reason it blocks calls to tools it has **never seen** in a list: a normal client
always asks for the list before using a tool. When you approve new rules that hide a tool, the
Shield applies them to calls at once, even if the client still keeps the old list in memory, and
tells the clients that support it to reload the list.

Protections can be relaxed **only** in the rules file, so only with your signed approval.
`verify` shows a warning for every relaxed protection:

```toml
version = 1

[protections]
results = "block"
outgoing_secrets = "log"
```

### Approving new or changed tools

```powershell
guardia shield tools list
guardia shield tools approve --server github
guardia shield tools approve --server github --tool create_issue
guardia shield tools forget --server github
```

- **list** shows, for every server, how many tools are approved and which are waiting, with the
  reason (new or changed) and part of their fingerprint.
- **approve** approves all the waiting tools of a server, or only the ones you name.
- **forget** deletes the memory of a server: at the next connection its tools will be stored again
  as if it were the first time.

After approving, restart the server connection in the client to see the tools.

**Rug pull** — a server that was harmless and secretly changes after you trusted it.
The tool memory (`scudo-strumenti.json`) is **signed**: if someone changes or deletes it, the
Shield notices (also thanks to the ledger) and hides all the tools of that server until you
approve them again.

## Where the file lives and why it must be approved

The file is `%LOCALAPPDATA%\GuardiaMCP\regole.toml` (the name is the same in every language).
When you approve it, Guardia saves a **signature** (`regole.firma`) made with the same key,
protected by Windows DPAPI, that signs the ledger.

**Signature** — a code computed from the file content with a secret key. If even one letter of the
file changes, the signature no longer matches.

Why? A malicious MCP server is a program running as your user: it could try to rewrite the rules
to free itself. If the Shield finds the file changed without a new approval, it goes into **full
lockdown**: it refuses every message and explains how to unlock it.

| Situation | What the Shield does |
|---|---|
| No file and no approval | Lets messages through and logs calls (default behavior) |
| File present but never approved | Full lockdown: "the rules are not approved" |
| File changed after approval | Full lockdown: "the file was changed" |
| Approved file then deleted | Full lockdown: "the approved file was deleted" |
| Signing key not readable | Full lockdown: approve the rules again |

## What the file looks like

```toml
version = 1
default = "allow"

[[rule]]
name = "Never touch SSH keys"
action = "block"
phase = "call"
argument.path = ["~/.ssh/**", "**/.ssh/**"]
```

- `version` is always `1`.
- `default` says what to do when no rule matches.
- Every `[[rule]]` has a **name**, an **action** and some **conditions**.
- A rule triggers only when **all** its conditions are true; inside a list, **one** matching value
  is enough.

Every key has an English and an Italian name, and you can mix them. The only exception is the
header: in the whole file use either `[[rule]]` or `[[regola]]`, not both.

### Keys

| English | Italiano | What it does | Example |
|---|---|---|---|
| `version` | `versione` | Format version, always 1 | `version = 1` |
| `default` | `predefinito` | Action when no rule matches | `default = "allow"` |
| `rule` | `regola` | One rule: `[[rule]]` | |
| `name` | `nome` | Rule name, shown in errors and in the ledger | `name = "No SSH"` |
| `action` | `azione` | What to do when the rule triggers | `action = "block"` |
| `enabled` | `attiva` | `false` to switch the rule off without deleting it | `enabled = false` |
| `note` | `nota` | A note for you, ignored by Guardia | `note = "added in October"` |
| `server` | `server` | Server name (the one given with `--server`) | `server = "github"` |
| `tool` | `strumento` | Tool or prompt name | `tool = ["delete_*"]` |
| `method` | `metodo` | MCP method | `method = "resources/read"` |
| `phase` | `fase` | When the rule applies | `phase = "call"` |
| `argument` | `argomento` | Conditions on the arguments of a call | `argument.path = "~/.ssh/**"` |
| `field` | `campo` | Look only at these arguments | `argument.field = "url"` |
| `path` | `percorso` | File paths | `argument.path = "**/.env"` |
| `host` | `host` | Web addresses to hit | `argument.host = "*.ngrok.io"` |
| `host_not_in` | `host_non_in` | Triggers for every address **outside** this list | `argument.host_not_in = ["github.com"]` |
| `contains` | `contiene` | Words or phrases, ignoring case | `argument.contains = "DROP TABLE"` |
| `regex` | `regex` | Regular expressions | `content.regex = "\\d{16}"` |
| `content` | `contenuto` | Conditions on the whole message text | `content.secrets = true` |
| `secrets` | `segreti` | Known keys and tokens (GitHub, GitLab, Slack, AWS, Google, OpenAI, Anthropic, JWT) | `content.secrets = true` |
| `max_size` | `dimensione_max` | Triggers when the message is larger than these bytes | `content.max_size = 1000000` |
| `rate` | `frequenza` | Limit on calls and server requests over time (results are never blocked by it) | `rate = { max = 30, seconds = 60 }` |
| `max` | `massimo` | Maximum number in the time window | |
| `seconds` | `secondi` | Length of the time window | |
| `protections` | `protezioni` | Section that tunes the built-in protections | `[protections]` |
| `approved_tools` | `strumenti_approvati` | Memory of approved tools | `approved_tools = true` |
| `analysis` | `analisi` | Real-time analysis of tools and instructions | `analysis = "high"` |
| `results` | `risultati` | Result checking | `results = "warn"` |
| `outgoing_secrets` | `segreti_in_uscita` | Secrets in arguments | `outgoing_secrets = "ask"` |
| `result_secrets` | `segreti_nei_risultati` | Secrets in results | `result_secrets = "redact"` |
| `credential_requests` | `richieste_credenziali` | Requests for passwords and credentials | `credential_requests = "block"` |

### Phases

| English | Italiano | When |
|---|---|---|
| `call` | `chiamata` | The AI asks the server for something: use a tool, read a resource, get a prompt |
| `result` | `risultato` | The server answers a call |
| `list` | `elenco` | The server shows its tool list: with `block` the tool is **hidden** from the AI |
| `server_request` | `richiesta_server` | The server asks the client for something: sampling, questions to the user (elicitation), also in the new multi-round-trip pattern |

Without `phase`, the rule applies in every phase where its conditions make sense. Conditions on
`argument` apply only in the `call` phase.

### Actions

| English | Italiano | What happens |
|---|---|---|
| `allow` | `consenti` | The message goes through |
| `log` | `registra` | It goes through and is written to the ledger |
| `redact` | `oscura` | It goes through, but the matching parts become `[REDACTED]` |
| `ask` | `chiedi` | The confirmation window opens; without an answer in 45 seconds it **blocks** |
| `block` | `blocca` | The message does not go through; the sender gets an error with the rule name |

**When several rules trigger, the strictest wins**: block > ask > redact > log > allow. The
order you write them in does not matter. So an `allow` rule cannot cancel a `block` rule: to make
exceptions, use `host_not_in` or more precise conditions.

**The default** applies to calls, lists and server requests, but **not to results**: if you
allowed a call, its result goes through (unless an explicit rule says otherwise). With
`default = "block"` you get an **allowlist**: only what you allow goes through.

## How values are compared

- **Names** (server, tool, method, host): `*` means any text, `?` one character. Case does not
  matter: `delete_*` also hits `Delete_Repo`.
- **Paths**: Guardia normalizes them before comparing.
  - `~`, `%USERPROFILE%` and `$HOME` become your user folder;
  - `\` becomes `/`;
  - `..` steps are resolved;
  - `file:///` addresses become paths;
  - Windows spellings that open the same file are reduced to the plain path: `\\?\C:\…`,
    `\\.\C:\…`, `\\localhost\C$\…`, trailing dots (`.ssh.`) and streams (`.env::$DATA`);
  - Windows short names of existing folders (such as `PROGRA~1`) are expanded to the full name.

  So `~/projects/../.ssh/id_rsa` becomes `~/.ssh/id_rsa`. In patterns, `*` does not cross
  folders while `**` does: `**/.env` hits `.env` in any folder.
- **Relative paths** (like `../../.ssh/id_rsa`) cannot be traced back to your user folder: to
  catch them, use patterns starting with `**/`, like `**/.ssh/**`.
- **Hosts**: Guardia looks for web addresses (`https://…`, `wss://…`, `ftp://…`) inside the
  arguments and extracts their name. `*.github.com` hits `api.github.com` but not `github.com`:
  if you want both, write both.
- **Secrets**: the most common key formats are recognized. A secret in an unusual format can slip
  through.

**Glob** — a pattern with `*` and `?` that means "any name that looks like this".
**Regular expression (regex)** — a more powerful language for describing text, for experts.
A badly written regex can be slow: prefer `contains` when it is enough.

## Recipes

Block a whole server:

```toml
[[rule]]
name = "Suspended server"
server = "old-server"
action = "block"
```

Ask before GitHub writes anything:

```toml
[[rule]]
name = "GitHub: ask before writing"
server = "github"
tool = ["create_*", "delete_*", "push_*", "merge_*", "update_*"]
action = "ask"
```

Data can only leave towards addresses you know:

```toml
[[rule]]
name = "Known addresses only"
phase = "call"
action = "block"
argument.host_not_in = ["github.com", "*.github.com", "api.openai.com"]
```

Allowlist: only what you explicitly allow goes through. Tools you do not allow are also hidden
from the list, because the default applies to the `list` phase too.

```toml
version = 1
default = "block"

[[rule]]
name = "Startup and lists"
phase = "call"
method = ["initialize", "tools/list", "ping", "server/discover"]
action = "allow"

[[rule]]
name = "Read-only tools"
tool = ["read_*", "list_*", "search_*", "get_*"]
action = "allow"
```

Hide tools whose description gives orders to the AI:

```toml
[[rule]]
name = "Suspicious descriptions"
phase = "list"
action = "block"
content.contains = ["ignore previous instructions", "<important>", "do not tell the user"]
```

Redact names and card numbers in results:

```toml
[[rule]]
name = "Personal data in results"
phase = "result"
action = "redact"
content.contains = ["Jane Doe"]
content.regex = ["\\b(?:\\d[ -]?){13,16}\\b"]
```

No server may ask you for a password:

```toml
[[rule]]
name = "No password requests"
phase = "server_request"
action = "block"
content.contains = ["password", "passcode", "one-time code"]
```

At most 30 calls per minute per server:

```toml
[[rule]]
name = "Call brake"
phase = "call"
method = "tools/call"
action = "block"
rate = { max = 30, seconds = 60 }
```

## What goes into the ledger

For every call to tools, resources and prompts, and for **every** decision other than "allow",
the ledger receives a `shield_decision` event with: server, phase, method, tool, action, rule
names and a **fingerprint** of the message.

**Fingerprint** — a code (SHA-256) computed from the message. It proves which message it was
without keeping its content.

Arguments and results are **never** written to the ledger. There are also `shield_start` and
`shield_stop` events for every session, `rules_approved` for every rules approval, and
`tools_pinned`, `tools_pending`, `tools_approved`, `tools_forgotten` for the tool memory, and
`shield_enabled`, `shield_disabled`, `shield_relinked` when Guardia connects, disconnects or
relinks a server.

## What the AI sees when a message is blocked

The client receives an MCP error with code `-32010` and a text such as:

> Blocked by Guardia MCP Shield. Rule: "Never touch SSH keys".

This way both you and the AI understand what happened and why.

## Honest limits

- The Shield sees **only MCP messages**. A malicious server is still a program on your PC and can
  read your files directly, without going through the AI. The Shield does not replace an
  antivirus or care about which servers you install.
- Rules are **patterns**, not understanding: text written on purpose to avoid them can succeed.
  The example rules are a starting point, not a guarantee.
- Signing the rules stops hidden changes, but anyone who can run code as your Windows user can
  also use the signing key.
- For now the Shield protects only local servers (stdio). Remote HTTP servers would require
  Guardia to forward network traffic: that is a separate decision.
- Anyone using your PC can answer the confirmation window: the Shield does not know who clicks.
- The tool memory trusts the **first time**: a server that is already malicious when first met is
  judged only by the analysis and by your rules.
- Result checking looks at the first million characters of each result.
- Credential requests are recognized by keywords in English and Italian, and only in forms that
  ask you for data (elicitation): a request worded differently, or a sampling request, can slip
  through. To control sampling, write a rule for the `server_request` phase.
- After you approve a tool, the client sees it only when it asks for the list again.
- With Claude Desktop from the Microsoft Store, if the Shield started by Claude is the first to
  create Guardia's data folder, Windows puts it in Claude's private folder
  (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local\GuardiaMCP`) and the app does not see
  it. Open Guardia once from its own icon before protecting servers.
- An AI app that rewrites its own configuration file can remove the Shield connection:
  `guardia shield list` always shows the current state.
- On Windows the server runs inside a job: when the Shield stops, is closed or crashes, the whole
  tree of programs started by the server ends too (for example `node` started by `npx`). A program
  started in the very first instant, before the job is applied, could escape; if Windows refuses
  the job, the Shield ends only the process it started.
- Commands that are `.cmd` or `.bat` files (such as `npx`) pass their arguments through
  `cmd.exe`: the Shield quotes them so that characters like `&` and `|` arrive intact and refuses
  arguments with line breaks, but, exactly as when the client starts the server, `cmd.exe` still
  expands `%NAME%`.

All of Guardia's limits are in [SECURITY.md](../SECURITY.md).
