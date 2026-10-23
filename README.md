# Guardia MCP

**by Alexander Puglisi**

> 🇬🇧 English below · 🇮🇹 Italiano più sotto

---

## 🇬🇧 English

Guardia MCP is a free, open source, fully offline defensive shield for AI agents
(Claude Code, Claude Desktop, Cursor, VS Code and others) that use tools through the
Model Context Protocol (MCP). No account, no telemetry, no data ever leaves your computer.

![Guardia MCP demo: command line scan, then the desktop app with overview, servers, findings and ledger](docs/demo-en.gif)

<sub>The demo runs on a fake PC made of fake servers and skills written for the purpose
(`scripts/demo.py`): no real data, no real secrets.</sub>

**Status: version 0.2.0 — v1 (static analysis) and v2 (real-time Shield for local stdio servers).**

- `guardia inventory` — finds every MCP server and skill on this PC (Claude Desktop, Claude Code,
  Cursor, VS Code, Windsurf, Gemini CLI, Codex, Copilot CLI) and lists them with a risk level.
- `guardia scan` — checks them against 88 rules and explains every problem with the exact file and
  line, a plain-language explanation and how to fix it:
  - **configuration**: dangerous commands, plain-text secrets, sensitive files, excessive
    permissions, suspicious network, unpinned packages, typosquatting;
  - **tools**: tool poisoning, hidden instructions (invisible Unicode, tag smuggling, encoded
    payloads), prompt injection, cross-server shadowing, misleading annotations;
  - **code**: decode-and-execute payloads, shell commands built from variable text, environment
    dumps, credential paths, AI agent config access, tunnel or exfiltration hosts, hard-coded secrets;
  - **dependencies**: install-time scripts (including the whole installed npm tree), git/URL
    dependencies, lookalike names, unpinned versions, missing lockfiles, install-time `setup.py`;
  - **skills**: `SKILL.md` text, granted tools, download-and-execute commands, attached scripts;
  - **rug pulls**: a local baseline of every tool and skill reports silent changes until accepted.
- **Tamper-evident ledger** — every scan is appended to a SHA-256 hash chain signed with an HMAC
  key protected by Windows DPAPI. `guardia ledger verify | show | anchor`.
- **Reports** — `--format text | json | html | sarif`. The HTML report is a single file with no
  scripts and a strict Content Security Policy; SARIF 2.1.0 works with GitHub code scanning.
- **Rules guide** — `guardia rules` lists all 88 rules, `guardia rules G05-002` explains one.
  The full guide is in [docs/RULES.md](docs/RULES.md) (generated from the code, always up to date).
- **Desktop app** — a borderless window with the sections centered at the top: overview, servers
  and skills, findings, Shield, ledger, reports and settings, each explained in one line, in Italian and English. It uses the same engine as the CLI, shows only text (never HTML from
  analyzed files), has no network access and a strict CSP.

The scan never runs the code it analyzes and never changes configuration files. Only the Shield
changes a client's configuration, and only when you confirm it (with a backup first). Guardia
keeps its own data (baseline, ledger, rules, tool memory, backups, app settings) in
`%LOCALAPPDATA%\GuardiaMCP`.

Exit codes of `guardia scan`: `0` nothing at or above `--fail-on` (default `high`),
`1` problems found, `2` usage error, `3` incomplete analysis.

Read [SECURITY.md](SECURITY.md) for what Guardia guarantees and its honest limits, and
[CONTRIBUTING.md](CONTRIBUTING.md) to help.

### Shield (v2)

The Shield sits between an AI app and a local MCP server: the client talks to Guardia, Guardia
talks to the server, and every message is checked before it passes.

```powershell
guardia shield list
guardia shield enable --server NAME --confirm
guardia shield rules example --save
guardia shield rules approve
```

- **Connects servers for you**: `guardia shield list` shows every server and whether it can be
  protected; `enable` saves a backup, changes only that server's entry and records the original;
  `disable` puts it back, never overwriting your own later edits. The same actions are in the
  **Shield** section of the app.
- **Your rules in TOML**, with English or Italian keys: allow, log, redact, ask or block a tool
  call, a result or a server request; match tools, paths, hosts and text; limit the call rate.
  Rules must be approved and are signed: if they are changed behind your back, the Shield blocks
  everything until you approve them again. `guardia shield rules test` tries a rule without a
  server.
- **Protection even without rules**: it remembers each server's tools and **hides tools that change
  or appear suddenly** until you approve them (`guardia shield tools approve`); it applies the 88
  v1 rules in real time to hide poisoned tools and remove dangerous server instructions; it flags
  prompt injection in results, redacts secrets in results, and stops secrets in arguments and
  requests for passwords. Hidden tools cannot be called either.
- **Asks you** in a small always-on-top window when a rule says `ask`: the AI cannot answer for you,
  and no answer within 60 seconds means **block**.
- **Fails closed**: only valid JSON-RPC messages pass, exactly as checked (duplicate keys, batches,
  unsolicited responses and oversized messages are dropped); if a check fails or the ledger cannot
  be written, the message is blocked or the server is not started. Every decision is recorded in
  the ledger.
- Supports MCP 2025-11-25 and 2026-07-28 over stdio, tested with the official MCP Python SDK, and
  adds about 0.06 ms per message. Remote (HTTP) servers are not protected yet.

Full guide: [docs/SHIELD.md](docs/SHIELD.md).

### Install from source (recommended)

Requires [uv](https://docs.astral.sh/uv/).

```powershell
cd C:\Progetti\GuardiaMCP
uv sync --extra app
uv run guardia inventory
uv run guardia scan
uv run guardia scan --format html --output guardia-report.html
uv run guardia ledger verify
uv run guardia rules G05-002
uv run guardia-app
```

### Windows executables

`scripts/build_exe.py` builds, with PyInstaller, a folder `dist\GuardiaMCP\` with two programs —
`guardia.exe` (command line) and `GuardiaMCP.exe` (desktop app) — plus a zip and a
`SHA256SUMS.txt` file with their fingerprints. Python is not needed to run them.

```powershell
cd C:\Progetti\GuardiaMCP
uv run --group build --extra app python scripts\build_exe.py
.\dist\GuardiaMCP\guardia.exe scan
.\dist\GuardiaMCP\GuardiaMCP.exe
```

The executables are **not code-signed yet**: Windows SmartScreen may warn the first time.
Before running a copy you did not build yourself, compare its SHA-256 with `SHA256SUMS.txt`
(`Get-FileHash .\GuardiaMCP.exe`).

License: [Apache 2.0](LICENSE).

---

## 🇮🇹 Italiano

Guardia MCP è uno scudo difensivo gratuito, open source e completamente offline per gli agenti AI
(Claude Code, Claude Desktop, Cursor, VS Code e altri) che usano strumenti tramite il
Model Context Protocol (MCP). Nessun account, nessuna telemetria, nessun dato esce dal tuo computer.

![Demo di Guardia MCP: scansione da riga di comando, poi l'app desktop con panoramica, server, problemi e registro](docs/demo-it.gif)

<sub>La demo gira su un PC finto, fatto di server e skill finti scritti apposta
(`scripts/demo.py`): nessun dato vero, nessun segreto vero.</sub>

**Stato: versione 0.2.0 — v1 (analisi statica) e v2 (Scudo in tempo reale per i server locali stdio).**

- `guardia inventario` — trova tutti i server MCP e le skill del PC (Claude Desktop, Claude Code,
  Cursor, VS Code, Windsurf, Gemini CLI, Codex, Copilot CLI) e li elenca con il livello di rischio.
- `guardia scansiona` — li controlla con 88 regole e spiega ogni problema con file e riga esatti,
  una spiegazione semplice e come correggerlo:
  - **configurazione**: comandi pericolosi, segreti in chiaro, file sensibili, permessi eccessivi,
    rete sospetta, pacchetti senza versione bloccata, typosquatting;
  - **strumenti**: tool poisoning, istruzioni nascoste (Unicode invisibile, caratteri «tag», testo
    codificato), prompt injection, interferenze tra server, annotazioni ingannevoli;
  - **codice**: codice decodificato ed eseguito, comandi di shell costruiti con testo variabile,
    variabili d'ambiente impacchettate, percorsi di credenziali, accesso alle configurazioni degli
    agenti AI, servizi di tunnel o raccolta dati, segreti scritti nel codice;
  - **dipendenze**: script eseguiti all'installazione (anche in tutto l'albero npm installato),
    dipendenze da git o URL, nomi simili a pacchetti famosi, versioni non bloccate, file di blocco
    mancanti, `setup.py` che esegue codice;
  - **skill**: testo di `SKILL.md`, strumenti concessi, comandi che scaricano ed eseguono, script allegati;
  - **rug pull**: una base di confronto locale di ogni strumento e skill segnala le modifiche
    nascoste finché non le accetti.
- **Registro a prova di manomissione** — ogni scansione viene aggiunta a una catena di hash SHA-256
  firmata con una chiave HMAC protetta da Windows DPAPI. `guardia registro verifica | mostra | ancora`.
- **Rapporti** — `--formato testo | json | html | sarif`. Il rapporto HTML è un file unico, senza
  script e con una Content Security Policy rigida; SARIF 2.1.0 funziona con GitHub code scanning.
- **Guida alle regole** — `guardia regole` elenca tutte le 88 regole, `guardia regole G05-002` ne
  spiega una. La guida completa è in [docs/REGOLE.md](docs/REGOLE.md) (generata dal codice,
  sempre aggiornata).
- **App desktop** — una finestra senza bordi con le sezioni al centro in alto: panoramica, server e
  skill, problemi, Scudo, registro, rapporti e impostazioni, ognuna spiegata in una riga, in italiano e inglese. Usa lo stesso motore della CLI, mostra solo testo (mai HTML preso dai file
  analizzati), non ha accesso alla rete e ha una CSP rigida.

La scansione non esegue mai il codice che analizza e non modifica i file di configurazione. Solo lo
Scudo modifica la configurazione di un client, e solo quando lo confermi (dopo averne salvato una
copia). Guardia tiene i propri dati (base di confronto, registro, regole, memoria degli strumenti,
copie di sicurezza, impostazioni dell'app) in `%LOCALAPPDATA%\GuardiaMCP`.

Codici di uscita di `guardia scansiona`: `0` nessun problema dal livello `--fallisci-da` in su
(predefinito `high`), `1` problemi trovati, `2` errore d'uso, `3` analisi incompleta.

Leggi [SECURITY.md](SECURITY.md) per sapere cosa garantisce Guardia e quali sono i suoi limiti, e
[CONTRIBUTING.md](CONTRIBUTING.md) per contribuire.

### Scudo (v2)

Lo Scudo si mette tra un'app AI e un server MCP locale: il client parla con Guardia, Guardia parla
con il server, e ogni messaggio viene controllato prima di passare.

```powershell
guardia scudo elenco
guardia scudo attiva --server NOME --conferma
guardia scudo regole esempio --salva
guardia scudo regole approva
```

- **Collega i server per te**: `guardia scudo elenco` mostra tutti i server e se si possono
  proteggere; `attiva` salva una copia di sicurezza, cambia solo la voce di quel server e annota
  quella originale; `disattiva` la rimette, senza mai sovrascrivere le tue modifiche successive. Le
  stesse azioni sono nella sezione **Scudo** dell'app.
- **Le tue regole in TOML**, con chiavi in italiano o in inglese: consenti, registra, oscura, chiedi
  o blocca una chiamata, un risultato o una richiesta del server; riconosce strumenti, percorsi,
  indirizzi e testo; limita la frequenza delle chiamate. Le regole vanno approvate e vengono
  firmate: se qualcuno le cambia di nascosto, lo Scudo blocca tutto finché non le riapprovi.
  `guardia scudo regole prova` prova una regola senza server.
- **Protezione anche senza regole**: ricorda gli strumenti di ogni server e **nasconde quelli che
  cambiano o compaiono all'improvviso** finché non li approvi (`guardia scudo strumenti approva`);
  applica in tempo reale le 88 regole della v1 per nascondere gli strumenti avvelenati e togliere
  le istruzioni pericolose del server; segnala la prompt injection nei risultati, oscura i segreti
  nei risultati e ferma i segreti negli argomenti e le richieste di password. Gli strumenti nascosti
  non si possono nemmeno chiamare.
- **Ti chiede conferma** in una piccola finestra sempre in primo piano quando una regola dice
  `chiedi`: l'AI non può rispondere al posto tuo, e senza risposta entro 60 secondi **blocca**.
- **Nel dubbio blocca**: passano solo messaggi JSON-RPC validi, esattamente come sono stati
  controllati (chiavi duplicate, lotti, risposte non richieste e messaggi troppo grandi vengono
  scartati); se un controllo va in errore o il registro non è scrivibile, il messaggio viene
  bloccato o il server non parte. Ogni decisione finisce nel registro.
- Supporta MCP 2025-11-25 e 2026-07-28 su stdio, è provato con l'SDK Python ufficiale di MCP e
  aggiunge circa 0,06 ms per messaggio. I server remoti (HTTP) non sono ancora protetti.

Guida completa: [docs/SCUDO.md](docs/SCUDO.md).

Vuoi capire MCP da zero? Leggi [docs/IMPARA-MCP.md](docs/IMPARA-MCP.md).

### Installare dal codice sorgente (consigliato)

Serve [uv](https://docs.astral.sh/uv/).

```powershell
cd C:\Progetti\GuardiaMCP
uv sync --extra app
uv run guardia inventario
uv run guardia scansiona
uv run guardia scansiona --formato html --salva guardia-report.html
uv run guardia registro verifica
uv run guardia regole G05-002
uv run guardia-app
```

### Eseguibili per Windows

`scripts/build_exe.py` costruisce con PyInstaller la cartella `dist\GuardiaMCP\` con due
programmi — `guardia.exe` (riga di comando) e `GuardiaMCP.exe` (app desktop) — più un archivio
zip e il file `SHA256SUMS.txt` con le loro impronte. Per usarli non serve Python.

```powershell
cd C:\Progetti\GuardiaMCP
uv run --group build --extra app python scripts\build_exe.py
.\dist\GuardiaMCP\guardia.exe scansiona
.\dist\GuardiaMCP\GuardiaMCP.exe
```

Gli eseguibili **non sono ancora firmati digitalmente**: la prima volta Windows SmartScreen
potrebbe mostrare un avviso. Prima di avviare una copia che non hai costruito tu, confronta la sua
impronta SHA-256 con `SHA256SUMS.txt` (`Get-FileHash .\GuardiaMCP.exe`).

Licenza: [Apache 2.0](LICENSE).
