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

**Status: version 0.1.0 (v1, static analysis).**

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
  and skills, findings, ledger, reports and settings, each explained in one line, in Italian and English. It uses the same engine as the CLI, shows only text (never HTML from
  analyzed files), has no network access and a strict CSP.

Guardia never runs the code it analyzes and never changes configuration files. It keeps its own
data (baseline, ledger, app settings) in `%LOCALAPPDATA%\GuardiaMCP`.

Exit codes of `guardia scan`: `0` nothing at or above `--fail-on` (default `high`),
`1` problems found, `2` usage error, `3` incomplete analysis.

Read [SECURITY.md](SECURITY.md) for what Guardia guarantees and its honest limits, and
[CONTRIBUTING.md](CONTRIBUTING.md) to help.

### Shield (v2, development preview)

`guardia shield --server NAME -- command arguments` starts a local MCP server behind Guardia: the
client talks to Guardia, Guardia talks to the server. Today (phase 2.0) the Shield already:

- accepts only valid JSON-RPC messages and forwards exactly what it checked (duplicate keys,
  batches, wrong ids and oversized messages are dropped);
- drops responses the server sends for requests nobody made;
- blocks a message, instead of letting it through, if its own check fails;
- refuses to start the server if it cannot write to the ledger, and records every session;
- supports MCP 2025-11-25 and 2026-07-28 over stdio and adds about 0.06 ms per message.

It does not apply user rules yet: they arrive in phase 2.1, together with the guide.

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

**Stato: versione 0.1.0 (v1, analisi statica).**

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
  skill, problemi, registro, rapporti e impostazioni, ognuna spiegata in una riga, in italiano e inglese. Usa lo stesso motore della CLI, mostra solo testo (mai HTML preso dai file
  analizzati), non ha accesso alla rete e ha una CSP rigida.

Guardia non esegue mai il codice che analizza e non modifica i file di configurazione. Tiene i propri
dati (base di confronto, registro, impostazioni dell'app) in `%LOCALAPPDATA%\GuardiaMCP`.

Codici di uscita di `guardia scansiona`: `0` nessun problema dal livello `--fallisci-da` in su
(predefinito `high`), `1` problemi trovati, `2` errore d'uso, `3` analisi incompleta.

Leggi [SECURITY.md](SECURITY.md) per sapere cosa garantisce Guardia e quali sono i suoi limiti, e
[CONTRIBUTING.md](CONTRIBUTING.md) per contribuire.

### Scudo (v2, anteprima di sviluppo)

`guardia scudo --server NOME -- comando argomenti` avvia un server MCP locale dietro Guardia: il
client parla con Guardia, Guardia parla con il server. Oggi (fase 2.0) lo Scudo già:

- accetta solo messaggi JSON-RPC validi e inoltra esattamente quello che ha controllato (chiavi
  duplicate, lotti di messaggi, id sbagliati e messaggi troppo grandi vengono scartati);
- scarta le risposte che il server invia a richieste che nessuno ha fatto;
- blocca un messaggio, invece di lasciarlo passare, se il suo stesso controllo va in errore;
- non avvia il server se non riesce a scrivere nel registro, e registra ogni sessione;
- supporta MCP 2025-11-25 e 2026-07-28 su stdio e aggiunge circa 0,06 ms per messaggio.

Non applica ancora regole scritte da te: arrivano nella fase 2.1, insieme alla guida.

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
