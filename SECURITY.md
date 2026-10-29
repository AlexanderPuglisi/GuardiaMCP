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

Reviewing the code? [AUDIT.md](AUDIT.md) lists where to look and which test checks each promise.

Each guarantee below is enforced by an automated test, not only by a promise.

| Guarantee | How it is enforced |
|---|---|
| Never runs the code it analyzes | No `eval`/`exec`, dynamic import or pickle anywhere in the source (`tests/test_tool_corpus.py`). `ctypes` is used only for Windows system calls: DPAPI in `secure_store.py`, and in `shield/windows.py` the job that ends a server's whole process tree, the expansion of short path names and the check for network drives (`tests/test_tool_corpus.py`). |
| Starts a process only for the Shield, and only the one you configured | `subprocess` is allowed in exactly one module, `shield/process.py`, which starts the server command written in your configuration and Guardia's own confirmation window, never through a shell (`tests/test_tool_corpus.py`). The scanner and the app never start programs; the app window is drawn by Microsoft Edge WebView2, which runs its own helper processes. |
| Never connects to the network | No network module is imported; `urllib.parse` is used only to read text (`tests/test_self_defense.py`). The desktop app page has `connect-src 'none'`. |
| Changes a configuration file only when you confirm it | The scanner writes only to `%LOCALAPPDATA%\GuardiaMCP` (baseline, ledger, app settings) and to the report files you choose. Only `guardia shield enable/disable --confirm` (or the button in the app, after a confirmation) changes a client file: it saves a backup first, changes only that server's entry, and writes nothing if the file changed meanwhile (`tests/test_shield_activation.py`). |
| Text from analyzed files can never become code | Terminal output escapes control and bidirectional characters; the HTML report has no scripts and a strict CSP; the desktop app builds the page with `textContent` only and refuses `innerHTML` (`tests/test_app.py`). |
| Secrets are not copied into reports | Known secret formats are replaced with `[REDACTED]`; secrets in environment variables are shown only as name and length. |
| Defensive file reading | Size limits (128 MB per configuration file, 64 MB for other files), nesting limit, duplicate-key detection, rejection of `NaN`/`Infinity` and of numbers too large to handle. Unreadable files are reported as a finding (G12-006, G12-007) and mark the analysis as incomplete instead of silently passing. Network shares (`\\server\share`, `\\wsl.localhost\…`) and mapped network drives found in configurations are never opened automatically: only a folder you pass yourself with `--project` is read. |
| Small attack surface | The CLI has **zero** runtime dependencies. Only the desktop app depends on `pywebview`, which on Windows brings `bottle`, `proxy-tools`, `typing-extensions`, `pythonnet`, `clr-loader`, `cffi` and `pycparser`. All versions are pinned in `uv.lock`, and the executables are built without the development tools (`--no-dev`). |
| Canary tripwires | A decoy secret you plant (`guardia canary create`) is watched by the Shield in the live traffic: if a server reads it and sends it back, the message is blocked and recorded with the `canary` label (`tests/test_shield_canary.py`). The decoy value is bait and is written in clear; the list of canaries is stored encrypted with DPAPI. |
| Encrypted rotating backups | `guardia backup create` writes an encrypted (DPAPI) snapshot of the ledger, approved rules and canaries, keeps the latest and deletes the old (`tests/test_backup.py`). |

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
- **The canary catches traffic, not the filesystem.** The Shield trips on a decoy only when it
  travels through a server connected to the Shield and appears within the scanned text. A server
  that reads the bait without sending it back, or buries it in a huge or encoded blob, can be
  missed. Plant the bait where a snooping server would read it, and treat a trip as a real signal.
- **Backups are encrypted for this Windows user only.** DPAPI ties the snapshot to your account on
  this PC: it cannot be decrypted on another machine or by another user. Carrying the copy off the
  PC is a manual step, on purpose (Guardia never uses the network). On non-Windows the snapshot is
  not encrypted.

**Rules are patterns, not understanding.** There is no AI by design. Rules can produce false alarms
and can miss new tricks. Because the project is open source, an attacker can read the rules and try
to write text that avoids them. Obfuscation beyond the supported decoders (Base64, hex, Unicode
tag characters and other invisible characters) will be missed. A known false alarm: server code
that lists sensitive paths only to block them (a deny list) can be reported as if it read them.

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
on your PC and can read your files directly, without using MCP. On Windows the server runs inside
a job, so when the Shield stops the programs it started in turn (for example `node` started by
`npx`) end too; a program started in the very first instant, before the job applies, could escape.
Commands that are `.cmd` or `.bat` files (such as `npx` on Windows) pass their arguments through
`cmd.exe`: the Shield quotes them and refuses line breaks, but `cmd.exe` still expands `%NAME%`,
exactly as when your client runs them.

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

Next to each program there is a small `.exe.config` file with `loadFromRemoteSources` turned on.
Windows marks every file extracted from a downloaded zip as "from the Internet", and without this
setting .NET refuses to load the window library shipped inside the folder (version 0.2.0 failed to
start with `Failed to resolve Python.Runtime.Loader.Initialize`). The setting applies only to
Guardia's two programs, which load .NET libraries only from their own folder; anyone who can replace
those files can already replace the program itself.

### Disclaimer and liability

Guardia MCP is free software provided **"as is", without any warranty**, under the Apache License 2.0 (see [LICENSE](LICENSE), sections 7–8). You use it at your own risk.

- **No warranty.** There is no guarantee that it is free of errors or fit for any particular purpose, and it is not a guarantee of security: read [Honest limits](#honest-limits).
- **Modified copies are not official.** Anyone is free to study and change the source — that is what open source means — but a modified copy is **not** Guardia MCP and is not supported by the author. If you change the code and it breaks, or breaks something else, that is not the author's responsibility.
- **No liability.** To the extent allowed by law, the author is not liable for any damage arising from the use, misuse, or modification of this software, including data loss or problems caused by other software on your computer.

Found a real problem in the official release? Report it privately (see above) — that is always welcome.

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

Stai controllando il codice? [AUDIT.md](AUDIT.md) dice dove guardare e quale test controlla ogni promessa.

Ogni garanzia è verificata da un test automatico, non solo promessa.

| Garanzia | Come viene verificata |
|---|---|
| Non esegue mai il codice che analizza | Nel sorgente non c'è nessun `eval`/`exec`, import dinamico o pickle (`tests/test_tool_corpus.py`). `ctypes` serve solo per chiamate di sistema di Windows: DPAPI in `secure_store.py`, e in `shield/windows.py` il job che chiude tutto l'albero di processi di un server, l'espansione dei nomi brevi dei percorsi e il controllo dei dischi di rete (`tests/test_tool_corpus.py`). |
| Avvia un processo solo per lo Scudo, e solo quello che hai configurato tu | `subprocess` è permesso in un solo modulo, `shield/process.py`, che avvia il comando del server scritto nella tua configurazione e la finestra di conferma di Guardia, mai tramite una shell (`tests/test_tool_corpus.py`). Lo scanner e l'app non avviano mai programmi; la finestra dell'app la disegna Microsoft Edge WebView2, che usa propri processi di supporto. |
| Non si collega mai alla rete | Nessun modulo di rete viene importato; `urllib.parse` serve solo a leggere testo (`tests/test_self_defense.py`). La pagina dell'app desktop ha `connect-src 'none'`. |
| Modifica un file di configurazione solo quando lo confermi | La scansione scrive solo in `%LOCALAPPDATA%\GuardiaMCP` (base di confronto, registro, impostazioni dell'app) e nei file di rapporto che scegli tu. Solo `guardia scudo attiva/disattiva --conferma` (o il pulsante nell'app, dopo una conferma) cambia un file di un client: prima salva una copia, cambia solo la voce di quel server e non scrive nulla se nel frattempo il file è cambiato (`tests/test_shield_activation.py`). |
| Il testo dei file analizzati non diventa mai codice | L'output nel terminale neutralizza i caratteri di controllo e bidirezionali; il rapporto HTML non ha script e ha una CSP rigida; l'app desktop costruisce la pagina solo con `textContent` e rifiuta `innerHTML` (`tests/test_app.py`). |
| I segreti non finiscono nei rapporti | I formati di segreto noti diventano `[REDACTED]`; i segreti nelle variabili d'ambiente compaiono solo come nome e lunghezza. |
| Lettura difensiva dei file | Limiti di dimensione (128 MB per i file di configurazione, 64 MB per gli altri file), limite di annidamento, controllo delle chiavi duplicate, rifiuto di `NaN`/`Infinity` e dei numeri troppo grandi. I file illeggibili vengono segnalati come problema (G12-006, G12-007) e rendono l'analisi incompleta invece di passare in silenzio. Le cartelle di rete (`\\server\condivisione`, `\\wsl.localhost\…`) e i dischi di rete trovati nelle configurazioni non vengono mai aperti in automatico: si legge solo una cartella che indichi tu con `--progetto`. |
| Poca superficie d'attacco | La CLI ha **zero** dipendenze. Solo l'app desktop dipende da `pywebview`, che su Windows porta con sé `bottle`, `proxy-tools`, `typing-extensions`, `pythonnet`, `clr-loader`, `cffi` e `pycparser`. Tutte le versioni sono bloccate in `uv.lock`, e gli eseguibili vengono costruiti senza gli strumenti di sviluppo (`--no-dev`). |
| Esche-trappola (canary) | Un segreto civetta che pianti (`guardia esca crea`) è sorvegliato dallo Scudo nel traffico dal vivo: se un server lo legge e lo rimanda, il messaggio viene bloccato e registrato con l'etichetta `canary` (`tests/test_shield_canary.py`). Il valore dell'esca è un'esca ed è scritto in chiaro; l'elenco delle esche è salvato cifrato con DPAPI. |
| Backup cifrati che ruotano | `guardia copia crea` scrive uno snapshot cifrato (DPAPI) di registro, regole approvate ed esche, tiene gli ultimi e cancella i vecchi (`tests/test_backup.py`). |

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
- **L'esca scatta sul traffico, non sul disco.** Lo Scudo riconosce un'esca solo quando passa da un
  server collegato allo Scudo e compare nel testo esaminato. Un server che legge l'esca senza
  rimandarla indietro, o che la nasconde in un blocco enorme o codificato, può sfuggire. Pianta
  l'esca dove un server curioso andrebbe a leggere, e considera uno scatto un segnale vero.
- **I backup sono cifrati solo per questo utente di Windows.** DPAPI lega lo snapshot al tuo account
  su questo PC: non si può decifrare su un'altra macchina o con un altro utente. Portare la copia
  fuori dal PC è un passo manuale, per scelta (Guardia non usa mai la rete). Fuori da Windows lo
  snapshot non è cifrato.

**Le regole sono schemi, non comprensione.** Non c'è intelligenza artificiale, per scelta. Le
regole possono dare falsi allarmi e non accorgersi di trucchi nuovi. Il progetto è open source,
quindi un attaccante può leggere le regole e provare a scrivere testi che le evitano. Gli
offuscamenti diversi da quelli che Guardia sa decodificare (Base64, esadecimale,
caratteri Unicode «tag» e altri caratteri invisibili) non vengono riconosciuti. Un falso allarme
noto: il codice di un server che elenca percorsi sensibili solo per bloccarli (una lista di
divieti) può essere segnalato come se li leggesse.

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
PC e può leggere i tuoi file direttamente, senza passare da MCP. Su Windows il server gira dentro
un job, quindi quando lo Scudo si ferma finiscono anche i programmi che ha avviato a sua volta (per
esempio `node` avviato da `npx`); un programma avviato nel primissimo istante, prima che il job
valga, potrebbe sfuggire. I comandi che sono file `.cmd` o `.bat` (come `npx` su Windows) passano i
loro argomenti attraverso `cmd.exe`: lo Scudo li mette tra virgolette e rifiuta gli a capo, ma
`cmd.exe` espande comunque `%NOME%`, esattamente come quando li avvia il tuo client.

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

Accanto a ogni programma c'è un piccolo file `.exe.config` con `loadFromRemoteSources` attivo.
Windows segna ogni file estratto da uno zip scaricato come «proveniente da Internet», e senza questa
impostazione .NET si rifiuta di caricare la libreria della finestra che sta dentro la cartella (la
versione 0.2.0 non partiva, con l'errore `Failed to resolve Python.Runtime.Loader.Initialize`).
L'impostazione vale solo per i due programmi di Guardia, che caricano librerie .NET soltanto dalla
loro cartella; chi riesce a sostituire quei file può già sostituire il programma stesso.

### Avvertenza e responsabilità

Guardia MCP è software libero fornito **«così com'è», senza alcuna garanzia**, con licenza Apache 2.0 (vedi [LICENSE](LICENSE), sezioni 7–8). Lo usi a tuo rischio.

- **Nessuna garanzia.** Non c'è garanzia che sia privo di errori o adatto a uno scopo particolare, e non è una garanzia di sicurezza: leggi i [limiti, detti onestamente](#limiti-detti-onestamente).
- **Le copie modificate non sono ufficiali.** Chiunque è libero di studiare e cambiare il codice — è il senso dell'open source — ma una copia modificata **non** è Guardia MCP e non è supportata dall'autore. Se cambi il codice e si rompe, o rompe qualcos'altro, non è responsabilità dell'autore.
- **Nessuna responsabilità.** Nei limiti consentiti dalla legge, l'autore non è responsabile di alcun danno derivante dall'uso, dall'uso improprio o dalla modifica di questo software, inclusa la perdita di dati o problemi causati da altri programmi sul tuo computer.

Hai trovato un problema vero nella versione ufficiale? Segnalalo in privato (vedi sopra) — è sempre benvenuto.
