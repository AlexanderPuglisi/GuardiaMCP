# Security policy · Politica di sicurezza

[English](#english) · [Italiano](#italiano)

---

## English

### Reporting a vulnerability

Please **do not open a public issue** for a vulnerability in Guardia MCP.
Use GitHub's private **"Report a vulnerability"** button (Security → Advisories) on the project
repository. Include:

- the Guardia version (`guardia --version`) and your operating system;
- the steps to reproduce;
- a minimal example made of **fake** files (a fake MCP configuration, a fake tool description).
  Never send real malware, real secrets or data from other people's systems.

This is a free project maintained in spare time: reports are handled on a best-effort basis, with
no guaranteed response time and no bug bounty. Only the latest release is supported.

### What Guardia guarantees by design

Each guarantee below is enforced by an automated test, not only by a promise.

| Guarantee | How it is enforced |
|---|---|
| Never runs the code it analyzes | No `eval`/`exec`, dynamic import or pickle anywhere in the source (`tests/test_tool_corpus.py`). The only `ctypes` use is the Windows DPAPI call in `secure_store.py`. |
| Starts a process only for the Shield, and only the one you configured | `subprocess` is allowed in exactly one module, `shield/process.py`, which starts the server command written in your configuration and Guardia's own confirmation window, never through a shell (`tests/test_tool_corpus.py`). The scanner and the app never start processes. |
| Never connects to the network | No network module is imported; `urllib.parse` is used only to read text (`tests/test_self_defense.py`). The desktop app page has `connect-src 'none'`. |
| Changes a configuration file only when you confirm it | The scanner writes only to `%LOCALAPPDATA%\GuardiaMCP` (baseline, ledger, app settings) and to the report files you choose. Only `guardia shield enable/disable --confirm` (or the button in the app, after a confirmation) changes a client file: it saves a backup first, changes only that server's entry, and writes nothing if the file changed meanwhile (`tests/test_shield_activation.py`). |
| Text from analyzed files can never become code | Terminal output escapes control and bidirectional characters; the HTML report has no scripts and a strict CSP; the desktop app builds the page with `textContent` only and refuses `innerHTML` (`tests/test_app.py`). |
| Secrets are not copied into reports | Known secret formats are replaced with `[REDACTED]`; secrets in environment variables are shown only as name and length. |
| Defensive file reading | Size limit (64 MB per file), nesting limit, duplicate-key detection, rejection of `NaN`/`Infinity` and of numbers too large to handle. Unreadable files are reported as a finding (G12-006, G12-007) instead of silently passing. Paths to network shares (`\\server\share`) found in configurations are never opened. |
| Small attack surface | The CLI has **zero** runtime dependencies. Only the desktop app depends on `pywebview` (with `pythonnet`, `clr-loader`, `proxy-tools`, `bottle` on Windows). All versions are pinned in `uv.lock`. |

### Honest limits

Guardia MCP is a useful layer, not a guarantee. Please read these limits before trusting a result.

**"No findings" does not mean "safe".** It means these rules found nothing.

**Static analysis only (version 1).**

- **What is not on disk cannot be read.** Remote servers (HTTP/SSE) expose their tools only when
  connected, so their tools are not analyzed unless you provide a JSON export with `--path`.
  Servers whose package was never downloaded (for example `npx` packages not in the cache),
  compiled programs (Go, Rust, `.exe`) and Docker images are not analyzed. These gaps are always
  shown in the coverage line, never hidden.
- **Dynamic tools can be missed.** Tool names and descriptions built at runtime (from variables,
  files or the network) may not be extracted. Literal strings and simple constants are supported.
- **Only Python and JavaScript/TypeScript code is analyzed.** Other languages are checked only at
  the configuration and manifest level.
- **Runtime behavior is invisible.** A server can show harmless descriptions on disk and different
  ones when running, or misbehave only on some inputs. The real-time Shield (version 2) addresses
  part of this, for the servers you connect to it.

**Rules are patterns, not understanding.** There is no AI by design. Rules can produce false alarms
and can miss new tricks. Because the project is open source, an attacker can read the rules and try
to write text that avoids them. Obfuscation beyond the supported decoders (Base64, hex, Unicode
tag characters and other invisible characters) will be missed.

**Rug-pull detection is trust on first use.** The first scan records what exists today as the
baseline; a server that was already malicious at that moment is judged only by the other rules.
Changes are detected only between scans, and server-side changes of remote servers are invisible.

**The ledger is tamper-evident, not tamper-proof.** Each event is chained with SHA-256 and signed
with an HMAC key protected by Windows DPAPI. Anyone who can run code as your Windows user can also
use that key: they could rebuild a complete, valid ledger or delete the whole folder. The only
defense is an **anchor saved outside the PC** (`guardia ledger anchor`), checked later with
`guardia ledger verify --anchor`. On macOS and Linux the key is not protected by the operating
system, only by file permissions.

**The scan does not block anything.** It reports. Only servers connected to the Shield are
checked while the agent is running.

**The Shield (v2) protects only what passes through it.** Only local (stdio) servers that you
connect to it are protected: remote (HTTP) servers, Claude Desktop extensions, plugins and
servers you start some other way are not. An AI app that rewrites its own configuration can
remove the connection: `guardia shield list` shows the current state. The tool memory trusts the first time it meets a server, result
checking looks at the first million characters, and credential requests are recognized by
English and Italian keywords. Rules and protections are patterns: text written to avoid them
can succeed. The confirmation window
shows who asks and why, but cannot know who clicks it. The signed rules file stops hidden changes, yet anyone who can run code as your
Windows user can also use the signing key. The Shield sees only MCP messages: a malicious server is still a program
on your PC and can read your files directly, without using MCP. On Windows, if a server does not
stop when asked, the Shield ends the process it started, but programs that process started in turn
(for example `node` started by `npx`) may keep running. Commands that are `.cmd` or `.bat` files
(such as `npx` on Windows) pass their arguments through `cmd.exe`, exactly as when your client runs
them: the Shield does not add this risk, but it does not remove it either.

**Claude Desktop from the Microsoft Store.** Windows gives Store apps a private copy of
`AppData`. If the Shield, started by Claude, is the first to create Guardia's data folder,
Windows puts it in Claude's private folder (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local`),
where the app and the command line do not see it: the rules you approve and the ledger they
show would not be the ones the Shield uses. Open Guardia once from its own icon before
protecting servers; once the real folder exists, Claude's programs use it too.

**A compromised PC cannot check itself.** If malware already runs with your privileges or as
administrator, it can alter Guardia, its data or its output. No local tool can fix that.

**Reports may contain sensitive information.** Paths (which include your Windows user name),
server names and short evidence excerpts are included. Redaction recognizes common secret formats
only; an unusual secret inside a tool description or code excerpt might not be recognized. Review a
report before sharing it.

**Platform coverage.** Guardia is developed and tested on Windows 11. macOS and Linux locations
are implemented but have not been tested on real machines.

**Desktop app.** It uses the Microsoft Edge WebView2 runtime included in Windows and the
`pywebview` library. The page runs with a strict Content Security Policy, no network access and no
developer tools. The app runs with your user's privileges.

**Windows executables.** `guardia.exe` and `GuardiaMCP.exe` are built with PyInstaller (pinned in
`uv.lock`) and contain a copy of Python and of the libraries above. They are **not code-signed
yet**, so Windows SmartScreen may warn, and some antivirus products occasionally flag PyInstaller
programs by mistake. Each build writes `SHA256SUMS.txt`: compare it with `Get-FileHash` before
running a copy you did not build yourself. Installing from source remains the most transparent
option.

---

## Italiano

### Segnalare una vulnerabilità

Per favore **non aprire una issue pubblica** per una vulnerabilità di Guardia MCP.
Usa il pulsante privato di GitHub **«Report a vulnerability»** (Security → Advisories) nel
repository del progetto. Indica:

- la versione di Guardia (`guardia --version`) e il sistema operativo;
- i passi per riprodurre il problema;
- un esempio minimo fatto di file **finti** (una configurazione MCP finta, una descrizione di
  strumento finta). Non inviare mai malware vero, segreti veri o dati presi da sistemi di altri.

È un progetto gratuito curato nel tempo libero: le segnalazioni vengono gestite appena possibile,
senza tempi di risposta garantiti e senza ricompense. È supportata solo l'ultima versione.

### Cosa garantisce Guardia per come è costruito

Ogni garanzia è verificata da un test automatico, non solo promessa.

| Garanzia | Come viene verificata |
|---|---|
| Non esegue mai il codice che analizza | Nel sorgente non c'è nessun `eval`/`exec`, import dinamico o pickle (`tests/test_tool_corpus.py`). L'unico uso di `ctypes` è la chiamata a DPAPI di Windows in `secure_store.py`. |
| Avvia un processo solo per lo Scudo, e solo quello che hai configurato tu | `subprocess` è permesso in un solo modulo, `shield/process.py`, che avvia il comando del server scritto nella tua configurazione e la finestra di conferma di Guardia, mai tramite una shell (`tests/test_tool_corpus.py`). Lo scanner e l'app non avviano mai processi. |
| Non si collega mai alla rete | Nessun modulo di rete viene importato; `urllib.parse` serve solo a leggere testo (`tests/test_self_defense.py`). La pagina dell'app desktop ha `connect-src 'none'`. |
| Modifica un file di configurazione solo quando lo confermi | La scansione scrive solo in `%LOCALAPPDATA%\GuardiaMCP` (base di confronto, registro, impostazioni dell'app) e nei file di rapporto che scegli tu. Solo `guardia scudo attiva/disattiva --conferma` (o il pulsante nell'app, dopo una conferma) cambia un file di un client: prima salva una copia, cambia solo la voce di quel server e non scrive nulla se nel frattempo il file è cambiato (`tests/test_shield_activation.py`). |
| Il testo dei file analizzati non diventa mai codice | L'output nel terminale neutralizza i caratteri di controllo e bidirezionali; il rapporto HTML non ha script e ha una CSP rigida; l'app desktop costruisce la pagina solo con `textContent` e rifiuta `innerHTML` (`tests/test_app.py`). |
| I segreti non finiscono nei rapporti | I formati di segreto noti diventano `[REDACTED]`; i segreti nelle variabili d'ambiente compaiono solo come nome e lunghezza. |
| Lettura difensiva dei file | Limite di dimensione (64 MB per file), limite di annidamento, controllo delle chiavi duplicate, rifiuto di `NaN`/`Infinity` e dei numeri troppo grandi. I file illeggibili vengono segnalati come problema (G12-006, G12-007) invece di passare in silenzio. I percorsi di rete (`\\server\condivisione`) trovati nelle configurazioni non vengono mai aperti. |
| Poca superficie d'attacco | La CLI ha **zero** dipendenze. Solo l'app desktop dipende da `pywebview` (con `pythonnet`, `clr-loader`, `proxy-tools`, `bottle` su Windows). Tutte le versioni sono bloccate in `uv.lock`. |

### Limiti, detti onestamente

Guardia MCP è uno strato di protezione utile, non una garanzia. Leggi questi limiti prima di
fidarti di un risultato.

**«Nessun problema trovato» non significa «sicuro».** Significa che queste regole non hanno
trovato nulla.

**Solo analisi statica (versione 1).**

- **Quello che non è sul disco non si può leggere.** I server remoti (HTTP/SSE) mostrano i loro
  strumenti solo quando ci si collega, quindi non vengono analizzati, a meno che tu non fornisca un
  export JSON con `--percorso`. Non vengono analizzati i server il cui pacchetto non è mai stato
  scaricato (per esempio pacchetti `npx` assenti dalla cache), i programmi compilati (Go, Rust,
  `.exe`) e le immagini Docker. Questi vuoti compaiono sempre nella riga della copertura, non
  vengono mai nascosti.
- **Gli strumenti dinamici possono sfuggire.** Nomi e descrizioni costruiti durante l'esecuzione
  (da variabili, file o rete) possono non essere estratti. Testi scritti direttamente e costanti
  semplici sono supportati.
- **Il codice analizzato è solo Python e JavaScript/TypeScript.** Gli altri linguaggi vengono
  controllati solo a livello di configurazione e manifest.
- **Il comportamento durante l'esecuzione non si vede.** Un server può avere descrizioni innocue sul
  disco e diverse quando è in funzione, o comportarsi male solo con certi input. Lo Scudo in tempo
  reale (versione 2) copre una parte di questo problema, per i server collegati a lui.

**Le regole sono schemi, non comprensione.** Non c'è intelligenza artificiale, per scelta. Le
regole possono dare falsi allarmi e non accorgersi di trucchi nuovi. Il progetto è open source,
quindi un attaccante può leggere le regole e provare a scrivere testi che le evitano. Gli
offuscamenti diversi da quelli che Guardia sa decodificare (Base64, esadecimale,
caratteri Unicode «tag» e altri caratteri invisibili) non vengono riconosciuti.

**Il controllo delle modifiche (rug pull) si fida della prima volta.** La prima scansione salva
come base quello che c'è oggi: un server che era già malevolo in quel momento viene giudicato solo
dalle altre regole. Le modifiche si vedono solo tra una scansione e l'altra, e quelle fatte sul
server remoto non si vedono.

**Il registro rivela le manomissioni, ma non le impedisce.** Ogni evento è incatenato con SHA-256 e
firmato con una chiave HMAC protetta da Windows DPAPI. Chi riesce a eseguire codice con il tuo
utente di Windows può usare anche quella chiave: potrebbe ricostruire un registro completo e valido,
oppure cancellare tutta la cartella. L'unica difesa è un'**ancora salvata fuori dal PC**
(`guardia registro ancora`), da controllare più avanti con `guardia registro verifica --ancora`.
Su macOS e Linux la chiave non è protetta dal sistema operativo, solo dai permessi dei file.

**La scansione non blocca nulla.** Segnala. Solo i server collegati allo Scudo vengono
controllati mentre l'agente lavora.

**Lo Scudo (v2) protegge solo quello che passa da lui.** Sono protetti solo i server locali (stdio)
che colleghi: i server remoti (HTTP), le estensioni di Claude Desktop, i plugin e i server avviati
in altro modo no. Un'app AI che riscrive la propria configurazione può togliere il collegamento:
`guardia scudo elenco` mostra lo stato attuale. La memoria degli strumenti si fida della prima volta che incontra un server,
il controllo dei risultati guarda il primo milione di caratteri e le richieste di credenziali
vengono riconosciute da parole chiave in italiano e inglese. Regole e protezioni sono schemi: un
testo scritto per aggirarle può riuscirci. La finestra di conferma
mostra chi chiede e perché, ma non può sapere chi clicca. Il file delle regole firmato ferma le modifiche di nascosto, ma chi
riesce a eseguire codice con il tuo utente di Windows può usare anche la chiave di firma. Lo Scudo
vede solo i messaggi MCP: un server malevolo resta un programma sul tuo
PC e può leggere i tuoi file direttamente, senza passare da MCP. Su Windows, se un server non si
ferma quando glielo si chiede, lo Scudo chiude il processo che ha avviato, ma i programmi avviati a
loro volta da quel processo (per esempio `node` avviato da `npx`) possono restare attivi. I comandi
che sono file `.cmd` o `.bat` (come `npx` su Windows) passano i loro argomenti attraverso `cmd.exe`,
esattamente come quando li avvia il tuo client: lo Scudo non aggiunge questo rischio, ma nemmeno
lo toglie.

**Claude Desktop installato dal Microsoft Store.** Windows dà alle app dello Store una copia
privata di `AppData`. Se il primo a creare la cartella dei dati di Guardia è lo Scudo avviato da
Claude, Windows la mette nella cartella privata di Claude
(`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local`), dove l'app e la riga di comando non la
vedono: le regole che approvi e il registro che vedi non sarebbero quelli usati dallo Scudo.
Apri Guardia una volta dalla sua icona prima di proteggere i server; quando la cartella vera
esiste, la usano anche i programmi di Claude.

**Un PC già compromesso non può controllare se stesso.** Se un malware gira già con i tuoi permessi
o come amministratore, può alterare Guardia, i suoi dati o i suoi risultati. Nessuno strumento
locale può rimediare.

**I rapporti possono contenere informazioni riservate.** Contengono percorsi (che includono il tuo
nome utente di Windows), nomi dei server e brevi estratti delle prove. L'oscuramento riconosce solo
i formati di segreto più comuni: un segreto insolito dentro una descrizione o un pezzo di codice
potrebbe non essere riconosciuto. Rileggi un rapporto prima di condividerlo.

**Sistemi supportati.** Guardia è sviluppato e testato su Windows 11. I percorsi di macOS e Linux
sono implementati ma non sono stati provati su computer reali.

**App desktop.** Usa il runtime Microsoft Edge WebView2 incluso in Windows e la libreria
`pywebview`. La pagina gira con una Content Security Policy rigida, senza accesso alla rete e senza
strumenti per sviluppatori. L'app ha i permessi del tuo utente.

**Eseguibili per Windows.** `guardia.exe` e `GuardiaMCP.exe` sono costruiti con PyInstaller (versione
bloccata in `uv.lock`) e contengono una copia di Python e delle librerie indicate sopra. **Non sono
ancora firmati digitalmente**: Windows SmartScreen può mostrare un avviso e alcuni antivirus a volte
segnalano per errore i programmi fatti con PyInstaller. Ogni build scrive `SHA256SUMS.txt`:
confrontalo con `Get-FileHash` prima di avviare una copia che non hai costruito tu. Installare dal
codice sorgente resta la scelta più trasparente.
