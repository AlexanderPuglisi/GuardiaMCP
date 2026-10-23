# The Guardia MCP Shield

**by Alexander Puglisi** · [Versione italiana](SCUDO.md)

The Shield is the part of Guardia that works **while** the AI is using MCP servers. The v1 scanner
reads files and tells you what is risky; the Shield sits between the messages and can **block,
hide or redact** them following rules you write.

> **Status: development preview (phase 2.1).** Rules work. The window for the `ask` action
> arrives in phase 2.3; until then `ask` **blocks**. Automatic client setup arrives in phase 2.4:
> for now you edit the configuration by hand (see below).

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
  "command": "C:\\Program Files\\GuardiaMCP\\guardia.exe",
  "args": ["shield", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
}
```

The same pattern works for Claude Code, Cursor and VS Code. In phase 2.4 Guardia will do it for
you, with a backup and a command to undo it.

## Rules in five minutes

```powershell
guardia shield rules example --save
guardia shield rules verify
guardia shield rules test --tool read_file --arguments '{"path": "~/.ssh/id_rsa"}'
guardia shield rules approve
guardia shield rules status
```

1. **example --save** creates the rules file with five rules that are useful for everyone.
2. Open the file with a text editor and adapt it.
3. **verify** checks the file and tells you line by line what is wrong, with a suggestion when
   you misspell a key.
4. **test** simulates a message and shows which decision the Shield would take, without starting
   any server.
5. **approve** checks the file, shows the differences from the last version and **signs** it.
   Running Shields use the new rules within one second.
6. **status** tells you whether the rules are active or the Shield is in full lockdown, and why.

The commands also exist in Italian: `guardia scudo regole verifica | approva | prova | esempio | stato`.
The example file is in English when your language is English (`--lang en`).

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
| `rate` | `frequenza` | Limit on calls over time | `rate = { max = 30, seconds = 60 }` |
| `max` | `massimo` | Maximum number in the time window | |
| `seconds` | `secondi` | Length of the time window | |

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
| `ask` | `chiedi` | Your confirmation is needed (for now it **blocks**; the window arrives in phase 2.3) |
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
  - `file:///` addresses become paths.

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
`shield_stop` events for every session, and `rules_approved` for every approval.

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
- `ask` blocks until the confirmation window arrives (phase 2.3).
- On Windows, programs started in turn by a server (for example `node` started by `npx`) may keep
  running if the server is closed by force.

All of Guardia's limits are in [SECURITY.md](../SECURITY.md).
