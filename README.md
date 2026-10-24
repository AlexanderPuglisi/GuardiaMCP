<p align="center">
  <img src="docs/banner.svg" alt="Guardia MCP: free, offline security shield for AI agents that use MCP, by Alexander Puglisi" width="100%">
</p>

**by Alexander Puglisi** · [alexanderpuglisiskilly.com](https://alexanderpuglisiskilly.com) · [Download](https://github.com/AlexanderPuglisi/GuardiaMCP/releases/latest) · [✓ Claude Academy: Introduction to MCP](https://academy.claude.com/verify/5a6125d6ee0ea408559c3679d0ff2657) · [✓ Claude Academy: MCP Advanced Topics](https://academy.claude.com/verify/d3957736dde1f145d365218c130d52fa)

**[Step-by-step guide with screenshots](docs/GUIDE.md)** · **[Guida passo passo con foto](docs/GUIDA.md)**

[![Tests](https://github.com/AlexanderPuglisi/GuardiaMCP/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/AlexanderPuglisi/GuardiaMCP/actions/workflows/tests.yml) · [How it was tested](TESTING.md) · [Security](SECURITY.md) · [For reviewers](AUDIT.md) · [Guide (EN)](docs/SHIELD.md) · [Guida (IT)](docs/SCUDO.md)

> 🇬🇧 English below · 🇮🇹 Italiano più sotto

---

## 🇬🇧 English

Guardia MCP is a free, open source, fully offline defensive shield for AI agents
(Claude Code, Claude Desktop, Cursor, VS Code and others) that use tools through the
Model Context Protocol (MCP). No account, no telemetry, no data ever leaves your computer.

### Already using Claude, Cursor or VS Code with MCP servers?

Every server you install can read files, use your keys and give instructions to the AI. Guardia
answers three questions in a minute:

- **Did I leave keys or passwords in plain text?** No need to open folder after folder: Guardia
  checks the MCP configurations, the skills and the code of the installed servers, and gives you the
  exact file and line, with how to fix it.
- **Is a server trying to trick the AI?** Hidden instructions in tool descriptions, invisible text,
  prompt injection.
- **Did something change behind my back?** A tool that was harmless yesterday and is not today.

And if you want, the **Shield** checks everything while the AI works: it blocks, hides secrets or
asks you first.

**Free, open source and offline.** No account, no data ever leaves your PC.

![Guardia MCP demo: command line scan, then the desktop app with overview, servers, findings and ledger](docs/demo-en.gif)

<sub>The demo runs on a fake PC made of fake servers and skills written for the purpose
(`scripts/demo.py`): no real data, no real secrets.</sub>

**Status: version 0.2.3 — v1 (static analysis) and v2 (real-time Shield for local stdio servers).**

- `guardia inventory` — finds the MCP servers and skills configured on this PC in the supported apps
  (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex, Copilot CLI) and lists
  them with a risk level.
- `guardia scan` — checks them against 90 rules and explains every problem with the exact file and
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
- **Rules guide** — `guardia rules` lists all 90 rules, `guardia rules G05-002` explains one.
  The full guide is in [docs/RULES.md](docs/RULES.md) (generated from the code, always up to date).
- **Desktop app** — a borderless window with the sections centered at the top: overview, servers
  and skills, findings, Shield, ledger, reports and settings, each explained in one line, in Italian and English. It uses the same engine as the CLI, shows only text (never HTML from
  analyzed files), has no network access and a strict CSP. Every settings change is written to the
  signed ledger and listed in *Settings → History of changes*, with the value before and after and a
  **Restore** button.

The scan never runs the code it analyzes and never changes configuration files: it writes only its
own notes (baseline and ledger). Only the Shield changes a client's configuration, and only when you
confirm it (with a backup first). Guardia keeps its own data (baseline, ledger, rules, tool memory,
backups, app settings) in `%LOCALAPPDATA%\GuardiaMCP`.

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
  or appear suddenly** until you approve them (`guardia shield tools approve --server NAME`); it
  applies in real time the v1 rules for tool descriptions and server instructions to hide poisoned
  tools and remove dangerous server instructions; it flags
  prompt injection in results, redacts secrets in results, and stops secrets in arguments and
  requests for passwords. Hidden tools cannot be called either.
- **Asks you** in a small always-on-top window when a rule says `ask`: the AI cannot answer for you,
  and no answer within 45 seconds means **block**.
- **Fails closed**: only valid JSON-RPC messages pass, exactly as checked (duplicate keys, batches,
  unsolicited responses and oversized messages are dropped); if a check fails or the ledger cannot
  be written, the message is blocked or the server is not started. Every decision is recorded in
  the ledger.
- Supports MCP 2025-11-25 and 2026-07-28 over stdio, tested with the official MCP Python SDK, and
  adds about 0.06 ms per message. Remote (HTTP) servers are not protected yet.

Full guide: [docs/SHIELD.md](docs/SHIELD.md).

### Getting started (no programming needed)

Prefer pictures? Follow the [step-by-step guide with screenshots](docs/GUIDE.md).

1. **Download** `GuardiaMCP-0.2.3-windows-x64.zip` and `SHA256SUMS.txt` from the project's
   [**Releases**](https://github.com/AlexanderPuglisi/GuardiaMCP/releases/latest) page on GitHub
   and check the zip: the [guide](docs/GUIDE.md#1-download-and-check) has two PowerShell lines to
   paste, which must print `True`.
2. **Extract** it to a folder that will not move, for example `C:\Users\YOUR-NAME` (the zip
   already contains the `GuardiaMCP` folder, so you get `C:\Users\YOUR-NAME\GuardiaMCP`).
   Protected servers start Guardia from this folder: if you move it, press **Relink to this
   Guardia** in the *Shield* section; if you want to delete it, first remove the protection (see
   *Uninstall*).
3. **Open `GuardiaMCP.exe`** (the one with the red shield icon). The first time Windows SmartScreen
   may warn you, because the program is not code-signed yet: choose *More info* → *Run anyway*. The
   first scan starts by itself.
4. **Read the results.** The card at the top gives the verdict in one sentence; *Findings* lists the
   problems from the most serious, each with the exact file and line (the small icon next to a path
   copies it), why it matters and how to fix it. The scan never changes your configuration files.
5. **Protect a server (optional).** Close the AI app (Claude, Cursor, VS Code…; Claude Desktop also
   from its tray icon → *Quit*). In *Shield*, press **Protect** next to a server and confirm:
   Guardia saves a backup and changes only that entry. Reopen the AI app: from now on every message
   of that server passes through the Shield. Tools that appear or change later stay hidden until you
   approve them in the same section.
6. **Your own rules (optional).** In *Shield* → *Shield rules* press **Create the example rules**:
   the editor opens with an example of 5 commented rules, not saved yet. Change what you want and
   press **Save and approve**; if something is wrong Guardia shows the line and saves nothing. When a
   rule says `ask`, a small Guardia window asks you; no answer within 45 seconds means **block**.
7. **Undo** any time with **Remove protection** next to the server.

To **update**, extract the new zip to the same place, replacing the files: your rules, ledger and
settings stay where they are ([details](docs/GUIDE.md#10-update-to-a-new-version)). Something not
working? The guide has a [troubleshooting table](docs/GUIDE.md#if-something-goes-wrong).

Everything is also available from the command line (`guardia.exe`), described below and in
[docs/SHIELD.md](docs/SHIELD.md). The guides are also inside the zip, in the `docs` folder.

> **Claude Desktop from the Microsoft Store.** Windows gives Store apps a private copy of the
> `AppData` folder. If a program started by Claude (such as the Shield) is the first to create
> Guardia's data folder, Windows puts it in Claude's private folder
> (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local\GuardiaMCP`), where the app and the command
> line do not see it. **Open Guardia once from its own icon before protecting servers**: once the
> real folder exists, everything uses it.

### Install from source (for developers, the most transparent option)

Requires [uv](https://docs.astral.sh/uv/).

```powershell
git clone https://github.com/AlexanderPuglisi/GuardiaMCP.git
cd GuardiaMCP
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
cd GuardiaMCP
uv run --exact --no-dev --group build --extra app python scripts\build_exe.py
.\dist\GuardiaMCP\guardia.exe scan
.\dist\GuardiaMCP\GuardiaMCP.exe
```

`--exact --no-dev` keeps the test tools out of the build, so the executables contain only Guardia,
Python and the libraries listed in [SECURITY.md](SECURITY.md). Afterwards `uv sync` brings the test
tools back.

The executables are **not code-signed yet**: Windows SmartScreen may warn the first time.
Before running a copy you did not build yourself, compare its SHA-256 with `SHA256SUMS.txt`
(`Get-FileHash .\GuardiaMCP.exe`).

### Uninstall

Guardia has no installer and leaves nothing hidden in the system: no services, no registry keys, no
automatic start. Remove it in this order:

1. Close the AI apps (Claude Desktop also from its tray icon → *Quit*) and **remove the Shield from
   every server**, otherwise the AI apps can no longer start those servers. The simplest way: open
   Guardia, go to *Shield* and press **Remove protection** next to each protected server, until the
   summary says 0. From PowerShell you can do it in one go (change the path if you extracted Guardia
   somewhere else):

   ```powershell
   & "$env:USERPROFILE\GuardiaMCP\guardia.exe" shield disable --all --confirm
   & "$env:USERPROFILE\GuardiaMCP\guardia.exe" shield list
   ```

   The list must show 0 protected servers. Entries you protected by hand (TOML files or files with
   comments) must be restored by hand: the original file is in the `backup` folder of Guardia's data
   (for each file, the oldest copy is the original).
2. Close Guardia.
3. Delete Guardia's data (ledger, rules, tool memory, backups, settings). **This cannot be
   undone**: copy the folder elsewhere first if you want to keep the history.

   ```powershell
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\GuardiaMCP"
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Packages\Claude_*\LocalCache\Local\GuardiaMCP" -ErrorAction SilentlyContinue
   ```

   The second line only matters with Claude Desktop from the Microsoft Store; if there is nothing
   there it does nothing.
4. Delete the folder you extracted and any shortcut you created.

### How I built it

I created Guardia MCP on my own: there is no team or company behind it. I decided what to build, how
it should work and what it must never do. To write the code I worked with **Claude Code**,
Anthropic's AI coding agent, which is listed as a contributor: every commit carries a
`Co-Authored-By: Claude` line, so the project history shows openly who did what.

- **My work**: I chose the principles (free for everyone, offline, no account, block when in doubt,
  rules in plain TOML, Italian and English), approved every phase before it was built, tested the
  app on my own PC and found real problems along the way (a path that would not paste into File
  Explorer, gaps around the maximized window, unclear texts), which we then fixed.
- **Claude's contribution**: it wrote the code, the tests and the documentation under my direction,
  one phase at a time, explaining every step to me.
- **The reviews**: before publishing, I had a separate Claude session review the whole project from
  scratch. It found 11 bugs, and we fixed every one of them, each with its own test. After the first
  release, I asked for four more reviews from scratch (scanner, Shield and command
  line, app, documentation): they reported 74 problems, and version 0.2.2 fixes 73 of them; the last
  one is written among the limits ([TESTING.md](TESTING.md)).

Before writing any code I studied the protocol with Anthropic's official course
([Claude Academy badge: Introduction to Model Context Protocol](https://academy.claude.com/verify/5a6125d6ee0ea408559c3679d0ff2657)). Then I built Guardia in
one intensive day, 23 October 2026: the static scanner (v1), the real-time Shield (v2.0 to v2.5) and
finally the review from scratch. The next day, while preparing version 0.2.2, I also completed the
advanced course ([Claude Academy badge: Model Context Protocol: Advanced Topics](https://academy.claude.com/verify/d3957736dde1f145d365218c130d52fa)).

— Alexander Puglisi

License: [Apache 2.0](LICENSE).

---

## 🇮🇹 Italiano

Guardia MCP è uno scudo difensivo gratuito, open source e completamente offline per gli agenti AI
(Claude Code, Claude Desktop, Cursor, VS Code e altri) che usano strumenti tramite il
Model Context Protocol (MCP). Nessun account, nessuna telemetria, nessun dato esce dal tuo computer.

### Usi già Claude, Cursor o VS Code con i server MCP?

Ogni server che installi può leggere file, usare le tue chiavi e dare istruzioni all'AI. Guardia
risponde in un minuto a tre domande:

- **Ho lasciato chiavi o password in chiaro?** Senza aprire cartella per cartella: Guardia controlla
  le configurazioni MCP, le skill e il codice dei server installati, e ti dà file e riga esatti, con
  il modo per sistemarli.
- **Qualche server sta provando a ingannare l'AI?** Istruzioni nascoste nelle descrizioni degli
  strumenti, testo invisibile, prompt injection.
- **È cambiato qualcosa di nascosto?** Uno strumento innocuo ieri che oggi non lo è più.

E se vuoi, lo **Scudo** controlla tutto mentre l'AI lavora: blocca, nasconde i segreti o ti chiede
conferma.

**Gratis, open source e offline.** Nessun account, nessun dato esce dal tuo PC.

![Demo di Guardia MCP: scansione da riga di comando, poi l'app desktop con panoramica, server, problemi e registro](docs/demo-it.gif)

<sub>La demo gira su un PC finto, fatto di server e skill finti scritti apposta
(`scripts/demo.py`): nessun dato vero, nessun segreto vero.</sub>

**Stato: versione 0.2.3 — v1 (analisi statica) e v2 (Scudo in tempo reale per i server locali stdio).**

- `guardia inventario` — trova i server MCP e le skill configurati sul PC nelle app supportate
  (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex, Copilot CLI) e li
  elenca con il livello di rischio.
- `guardia scansiona` — li controlla con 90 regole e spiega ogni problema con file e riga esatti,
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
- **Guida alle regole** — `guardia regole` elenca tutte le 90 regole, `guardia regole G05-002` ne
  spiega una. La guida completa è in [docs/REGOLE.md](docs/REGOLE.md) (generata dal codice,
  sempre aggiornata).
- **App desktop** — una finestra senza bordi con le sezioni al centro in alto: panoramica, server e
  skill, problemi, Scudo, registro, rapporti e impostazioni, ognuna spiegata in una riga, in italiano e inglese. Usa lo stesso motore della CLI, mostra solo testo (mai HTML preso dai file
  analizzati), non ha accesso alla rete e ha una CSP rigida. Ogni modifica alle impostazioni viene
  scritta nel registro firmato ed elencata in *Impostazioni → Cronologia delle modifiche*, con il valore
  prima e dopo e un pulsante **Ripristina**.

La scansione non esegue mai il codice che analizza e non modifica i file di configurazione: scrive
soltanto i propri appunti (base di confronto e registro). Solo lo Scudo modifica la configurazione di
un client, e solo quando lo confermi (dopo averne salvato una copia). Guardia tiene i propri dati
(base di confronto, registro, regole, memoria degli strumenti, copie di sicurezza, impostazioni
dell'app) in `%LOCALAPPDATA%\GuardiaMCP`.

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
  cambiano o compaiono all'improvviso** finché non li approvi
  (`guardia scudo strumenti approva --server NOME`); applica in tempo reale le regole della v1 su
  descrizioni degli strumenti e istruzioni del server per nascondere gli strumenti avvelenati e
  togliere le istruzioni pericolose; segnala la prompt injection nei risultati, oscura i segreti
  nei risultati e ferma i segreti negli argomenti e le richieste di password. Gli strumenti nascosti
  non si possono nemmeno chiamare.
- **Ti chiede conferma** in una piccola finestra sempre in primo piano quando una regola dice
  `chiedi`: l'AI non può rispondere al posto tuo, e senza risposta entro 45 secondi **blocca**.
- **Nel dubbio blocca**: passano solo messaggi JSON-RPC validi, esattamente come sono stati
  controllati (chiavi duplicate, lotti, risposte non richieste e messaggi troppo grandi vengono
  scartati); se un controllo va in errore o il registro non è scrivibile, il messaggio viene
  bloccato o il server non parte. Ogni decisione finisce nel registro.
- Supporta MCP 2025-11-25 e 2026-07-28 su stdio, è provato con l'SDK Python ufficiale di MCP e
  aggiunge circa 0,06 ms per messaggio. I server remoti (HTTP) non sono ancora protetti.

Guida completa: [docs/SCUDO.md](docs/SCUDO.md).

Vuoi capire MCP da zero? Leggi [docs/IMPARA-MCP.md](docs/IMPARA-MCP.md).

### Primi passi (non serve saper programmare)

Preferisci le foto? Segui la [guida passo passo con le schermate](docs/GUIDA.md).

1. **Scarica** `GuardiaMCP-0.2.3-windows-x64.zip` e `SHA256SUMS.txt` dalla pagina
   [**Releases**](https://github.com/AlexanderPuglisi/GuardiaMCP/releases/latest) del progetto su
   GitHub e controlla lo zip: nella [guida](docs/GUIDA.md#1-scarica-e-controlla) ci sono due righe
   da incollare in PowerShell, che devono stampare `True`.
2. **Estrailo** in una cartella che non sposterai, per esempio `C:\Users\TUO-NOME` (lo zip
   contiene già la cartella `GuardiaMCP`, quindi ottieni `C:\Users\TUO-NOME\GuardiaMCP`).
   I server protetti avviano Guardia da questa cartella: se la sposti, premi **Ricollega a questa
   Guardia** nella sezione *Scudo*; se vuoi cancellarla, prima togli la protezione (vedi
   *Disinstallare*).
3. **Apri `GuardiaMCP.exe`** (quello con l'icona dello scudo rosso). La prima volta Windows
   SmartScreen può mostrare un avviso, perché il programma non è ancora firmato digitalmente: scegli
   *Ulteriori informazioni* → *Esegui comunque*. La prima scansione parte da sola.
4. **Leggi i risultati.** Il riquadro in alto dà il verdetto in una frase; *Problemi* elenca i
   problemi dal più grave, ognuno con file e riga esatti (la piccola icona accanto a un percorso lo
   copia), perché è un rischio e come correggerlo. La scansione non cambia mai i file di
   configurazione.
5. **Proteggi un server (facoltativo).** Chiudi l'app AI (Claude, Cursor, VS Code…; Claude Desktop
   anche dalla sua icona vicino all'orologio → *Esci*). In *Scudo* premi **Proteggi** accanto a un
   server e conferma: Guardia salva una copia di sicurezza e cambia solo quella voce. Riapri l'app
   AI: da quel momento ogni messaggio di quel server passa dallo Scudo. Gli strumenti che compaiono o
   cambiano dopo restano nascosti finché non li approvi nella stessa sezione.
6. **Le tue regole (facoltativo).** In *Scudo* → *Regole dello Scudo* premi **Crea le regole
   d'esempio**: si apre l'editor con un esempio di 5 regole commentate, non ancora salvato. Cambia
   quello che vuoi e premi **Salva e approva**; se c'è un errore Guardia ti mostra la riga e non
   salva niente. Quando una regola dice `chiedi`, una piccola finestra di Guardia ti chiede
   conferma; senza risposta entro 45 secondi **blocca**.
7. **Torna indietro** quando vuoi con **Togli protezione** accanto al server.

Per **aggiornare**, estrai il nuovo zip nello stesso posto sostituendo i file: regole, registro e
impostazioni restano dove sono ([dettagli](docs/GUIDA.md#10-aggiornare-a-una-nuova-versione)).
Qualcosa non va? Nella guida c'è una [tabella dei problemi comuni](docs/GUIDA.md#se-qualcosa-non-va).

Tutto si può fare anche da riga di comando (`guardia.exe`), come spiegato sotto e in
[docs/SCUDO.md](docs/SCUDO.md). Le guide sono anche dentro lo zip, nella cartella `docs`.

> **Claude Desktop installato dal Microsoft Store.** Windows dà alle app dello Store una copia
> privata della cartella `AppData`. Se il primo a creare la cartella dei dati di Guardia è un
> programma avviato da Claude (per esempio lo Scudo), Windows la mette nella cartella privata di
> Claude (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local\GuardiaMCP`), dove l'app e la riga
> di comando non la vedono. **Apri Guardia una volta dalla sua icona prima di proteggere i
> server**: quando la cartella vera esiste, tutti usano quella.

### Installare dal codice sorgente (per sviluppatori, la scelta più trasparente)

Serve [uv](https://docs.astral.sh/uv/).

```powershell
git clone https://github.com/AlexanderPuglisi/GuardiaMCP.git
cd GuardiaMCP
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
cd GuardiaMCP
uv run --exact --no-dev --group build --extra app python scripts\build_exe.py
.\dist\GuardiaMCP\guardia.exe scansiona
.\dist\GuardiaMCP\GuardiaMCP.exe
```

`--exact --no-dev` lascia fuori dalla build gli strumenti di test, così gli eseguibili contengono
solo Guardia, Python e le librerie elencate in [SECURITY.md](SECURITY.md). Dopo, `uv sync` rimette
gli strumenti di test.

Gli eseguibili **non sono ancora firmati digitalmente**: la prima volta Windows SmartScreen
potrebbe mostrare un avviso. Prima di avviare una copia che non hai costruito tu, confronta la sua
impronta SHA-256 con `SHA256SUMS.txt` (`Get-FileHash .\GuardiaMCP.exe`).

### Disinstallare

Guardia non ha un programma di installazione e non lascia nulla di nascosto nel sistema: niente
servizi, niente chiavi di registro, niente avvio automatico. Toglila in quest'ordine:

1. Chiudi le app AI (Claude Desktop anche dalla sua icona vicino all'orologio → *Esci*) e **togli lo
   Scudo da tutti i server**, altrimenti le app AI non riescono più ad avviarli. Il modo più
   semplice: apri Guardia, vai in *Scudo* e premi **Togli protezione** accanto a ogni server
   protetto, finché il riepilogo dice 0. Da PowerShell puoi farlo in un colpo solo (cambia il
   percorso se hai estratto Guardia altrove):

   ```powershell
   & "$env:USERPROFILE\GuardiaMCP\guardia.exe" scudo disattiva --tutti --conferma
   & "$env:USERPROFILE\GuardiaMCP\guardia.exe" scudo elenco
   ```

   L'elenco deve mostrare 0 server protetti. Le voci protette a mano (file TOML o con commenti)
   vanno ripristinate a mano: il file originale è nella cartella `backup` dei dati di Guardia (per
   ogni file la copia più vecchia è l'originale).
2. Chiudi Guardia.
3. Cancella i dati di Guardia (registro, regole, memoria degli strumenti, copie di sicurezza,
   impostazioni). **Non si può annullare**: se vuoi tenere lo storico, copia prima la cartella
   altrove.

   ```powershell
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\GuardiaMCP"
   Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Packages\Claude_*\LocalCache\Local\GuardiaMCP" -ErrorAction SilentlyContinue
   ```

   La seconda riga serve solo con Claude Desktop installato dal Microsoft Store; se lì non c'è
   niente, non fa niente.
4. Cancella la cartella che avevi estratto e gli eventuali collegamenti.

### Come l'ho costruito

Guardia MCP l'ho creato io, da solo: non c'è un team né un'azienda dietro. Ho deciso cosa costruire,
come doveva funzionare e cosa non doveva mai fare. Per scrivere il codice ho lavorato con
**Claude Code**, l'agente di programmazione AI di Anthropic, che compare tra i contributori: ogni
commit porta la riga `Co-Authored-By: Claude`, così la storia del progetto mostra con trasparenza
chi ha fatto cosa.

- **Il mio lavoro**: ho scelto i principi (gratis per tutti, offline, nessun account, nel dubbio
  blocca, regole in TOML semplice, italiano e inglese), ho approvato ogni fase prima che venisse
  costruita, ho provato l'app sul mio PC e ho trovato problemi veri lungo la strada (un percorso che
  non si incollava in Esplora risorse, spifferi intorno alla finestra ingrandita, testi poco
  chiari), che abbiamo poi corretto.
- **Il contributo di Claude**: ha scritto il codice, i test e la documentazione sotto la mia guida,
  una fase alla volta, spiegandomi ogni passo.
- **Le revisioni**: prima di pubblicare ho fatto rivedere tutto il progetto da zero a una sessione
  separata di Claude. Ha trovato 11 bug, e li abbiamo corretti tutti, ciascuno con il suo test. Dopo
  la prima pubblicazione ho chiesto altre quattro revisioni da zero
  (scanner, Scudo e riga di comando, app, documentazione): hanno segnalato 74 problemi, e la versione
  0.2.2 ne corregge 73; l'ultimo è scritto tra i limiti ([TESTING.md](TESTING.md)).

Prima di scrivere codice ho studiato il protocollo con il corso ufficiale di Anthropic
([badge Claude Academy: Introduction to Model Context Protocol](https://academy.claude.com/verify/5a6125d6ee0ea408559c3679d0ff2657)). Poi ho costruito Guardia
in una giornata intensa, il 23 ottobre 2026: lo scanner statico (v1), lo Scudo in tempo reale
(dalla v2.0 alla v2.5) e infine la revisione da zero. Il giorno dopo, mentre preparavo la versione
0.2.2, ho completato anche il corso avanzato ([badge Claude Academy: Model Context Protocol: Advanced Topics](https://academy.claude.com/verify/d3957736dde1f145d365218c130d52fa)).

— Alexander Puglisi

Licenza: [Apache 2.0](LICENSE).
