# How Guardia was tested · Come è stato testato Guardia

[English](#english) · [Italiano](#italiano)

---

## English

A security tool is only worth what its tests prove. This page lists what was actually run on
version 0.2.3, how, and what is **not** covered. Nothing here was run against real malware or
anyone else's systems: every "attack" is a fake server or fake file written for the purpose.

### In numbers

| | |
|---|---|
| Automated tests | **846**, all passing (`uv run pytest`) |
| Automatic check on GitHub | lint, types and all tests on a clean Windows machine, for every change ([Tests](https://github.com/AlexanderPuglisi/GuardiaMCP/actions/workflows/tests.yml)) |
| Test files | 35 |
| Fake samples (configurations, servers, code, skills) | 84 files in `tests/corpus/` |
| Static rules, each with at least one malicious and one harmless fake case | 90 |
| Lint and types | `ruff` and `mypy --strict`: no issues |

### What the tests cover

- **Scanner.** Every one of the 90 rules is tested on a malicious fake case and on a harmless case
  that looks similar on purpose, to keep false alarms down. The tests also cover hostile input:
  huge or deeply nested files, duplicate JSON keys, `NaN`/`Infinity`, invisible Unicode, very large
  numbers.
- **Real-time Shield.** A fake MCP server (`tests/corpus/shield/fake_server.py`) can misbehave on
  request. It can:
  - send noise, spoofed responses and duplicate keys;
  - send server requests, huge messages, poisoned tools and hidden instructions;
  - change its tools after approval (a "rug pull"), or list the same tool twice;
  - inject text into results, refuse to stop, or send invalid Unicode.

  The tests check that the Shield blocks, hides or drops what it must and never lets a message
  through when its own check fails.
- **Official MCP SDK.** `tests/test_shield_sdk.py` runs a client and a server built with the official
  MCP Python SDK through the Shield, on both protocol versions (2025-11-25 and 2026-07-28). The SDK
  is a development-only dependency: Guardia itself does not depend on it.
- **Promises.** No network code, one single place that starts programs, no hidden code, strict page
  security: each promise has a test that fails if it is broken. See [AUDIT.md](AUDIT.md).
- **Ledger and signed files.** Deleted, changed or missing lines, a deleted ledger, a changed rules
  file and a deleted tool memory are all detected.
- **Client configurations.** Backups are written before every change. Your own later edits are
  never overwritten, and a file that changed meanwhile is left untouched.

### Checks beyond the automated tests

- **Mutation checks.** At the critical points, the code was broken on purpose (for example removing
  the check that refuses an unapproved rules file, or bypassing the Shield) to confirm that a test
  fails. These were done by hand on the most important checks, not with an automated mutation tool.
- **Windows executables.** `guardia.exe` was driven by the official SDK client: protocol 2026-07-28,
  a normal call passed, an attempt to read an SSH key was blocked, and the confirmation window
  opened from the executable and returned the answer. The command line gave the same results as the
  Python version on a real PC (read only).
- **Windows executables of 0.2.3.** Built without the development tools. The release zip was
  extracted and every file marked as downloaded from the Internet, as Windows does. From there,
  on a fake user folder: the command line scanned, the Shield protected a fake server and passed
  a request through the protected entry, the confirmation window opened and blocked by itself at
  the end of its countdown, and the app opened its window and closed normally.
- **Real window.** On a real screen, the maximized window covered exactly the work area
  computed by Windows (2560×1386, taskbar excluded) and went back to the same place when restored.
- **Speed.** The Shield adds about 0.06 ms per message.

### First review (version 0.2.0)

Before release, a separate Claude Code session reviewed the whole project from scratch, without
the context of the session that wrote it. It found **11 real bugs**. Each one got a test that
failed first, then a fix, then the same test passing:

1. protecting a server from the desktop app wrote the app's own program instead of `guardia.exe`;
2. a network path (`\\server\share\…`) written in a configuration could be opened by the scan;
3. a server could list the same tool twice to slip a changed copy past the tool memory;
4. Windows spellings of a path (`\\?\C:\…`, a trailing dot, `::$DATA`) could dodge path rules;
5. hostile values (invalid Unicode, giant numbers, TOML dates) could crash the scan or the Shield;
6. four ledger issues, including a deleted ledger reported as intact;
7. secrets written inside longer arguments (`Authorization: Bearer …`) could reach reports;
8. "Remove protection" in the app affected every server with the same name;
9. a fake test file was deleted by Windows Defender on clean machines;
10. the scan followed Windows junctions, causing duplicate results and very long scans;
11. "remember for 10 minutes" did not cover calls that were already waiting.

The documentation was corrected in the same pass wherever it promised more than the code did.

### Second review (version 0.2.2)

After the first public release, four more Claude Code sessions reviewed the project from
scratch, each on one area and each with fake data only:

- **the scanner on realistic setups** (paths with spaces, OneDrive folders, global npm and uv
  installs, VS Code profiles, Codex and Copilot files): **20** problems, mostly false alarms;
- **the Shield and the command line**, driven like a real client: **19** problems;
- **the desktop app**, screen by screen: **21** problems;
- **the documentation**, read as a beginner would: **14** problems.

73 of these 74 problems are fixed in 0.2.2. The code fixes come with automated tests (200 new
tests since 0.2.1); the app was also checked on screenshots in both languages and at two window
sizes, and the documentation by hand. The one problem left is a known limit, written in
[SECURITY.md](SECURITY.md): code that lists sensitive paths only to block them can be reported
as if it read them.

Among the most important fixes:

1. names like `GIT_AUTHOR_NAME` or `--auth-mode` were reported as exposed secrets, and ordinary
   skill and tool texts as tool poisoning; the default Shield then hid useful tools such as
   `send_email`;
2. a path with a space (for example `C:\Users\Mario Rossi\…`) switched off the code analysis,
   so a poisoned server could look clean;
3. one malformed Unicode character in a configuration or in a server's code stopped the whole
   scan;
4. any program named `guardia.exe` counted as "protected", and its real command was not
   analyzed;
5. the Shield could crash when the server closed first, and a rate limit could block the result
   of a call that had already run;
6. on Windows, stopping a server could leave its own child programs (such as `node` started by
   `npx`) running;
7. a request cancelled by the AI app while waiting for your confirmation was still carried out;
8. protecting servers could stop halfway on a read-only file, leaving nothing to undo with.

### Found after release

Version 0.2.0 did not start on a second Windows laptop when downloaded from GitHub: Windows marks
files extracted from a downloaded zip as "from the Internet", and .NET refused to load the window
library (`Failed to resolve Python.Runtime.Loader.Initialize`). The problem was reproduced here by
marking every file of the release zip the same way, fixed in 0.2.1 with a `.exe.config` next to
each program, and checked again: with the fix both the app and the confirmation window open, without
it the same error comes back. A test keeps the configuration in the build.

In version 0.2.2 the animated glowing border never appeared with the window maximized, which is
how the app opens since that version, and when the window was smaller it was only a 1-pixel line.
Version 0.2.3 replaces it with a soft red halo that travels along the edge in every window state.
It was checked on the real app, with pictures of the window a few seconds apart, and a test keeps
it visible.

### Not covered

- **macOS and Linux**: the code paths exist, but they were not tried on real machines.
- **Remote (HTTP) MCP servers**: not supported by the Shield yet, so not tested.
- **Real malware**: never used, by choice. The fake cases reproduce the techniques, not real
  payloads.
- **Code signing**: the executables are not signed yet. Compare them with `SHA256SUMS.txt`.

### Run it yourself

```powershell
uv sync --extra app
uv run pytest
uv run ruff check src tests scripts packaging
uv run mypy
```

GitHub runs the same checks on a clean Windows machine for every change
([`.github/workflows/tests.yml`](https://github.com/AlexanderPuglisi/GuardiaMCP/blob/main/.github/workflows/tests.yml)). The result is the **Tests** badge at
the top of the README.

---

## Italiano

Uno strumento di sicurezza vale quanto dimostrano i suoi test. Qui c'è cosa è stato eseguito
davvero sulla versione 0.2.3, come, e cosa **non** è coperto. Niente è stato provato con malware
vero o su sistemi di altri: ogni «attacco» è un server finto o un file finto scritto apposta.

### In numeri

| | |
|---|---|
| Test automatici | **846**, tutti passati (`uv run pytest`) |
| Controllo automatico su GitHub | stile, tipi e tutti i test su un Windows pulito, a ogni modifica ([Tests](https://github.com/AlexanderPuglisi/GuardiaMCP/actions/workflows/tests.yml)) |
| File di test | 35 |
| Esempi finti (configurazioni, server, codice, skill) | 84 file in `tests/corpus/` |
| Regole statiche, ognuna con almeno un caso finto malevolo e uno innocuo | 90 |
| Stile e tipi | `ruff` e `mypy --strict`: nessun problema |

### Cosa coprono i test

- **Scanner.** Ognuna delle 90 regole è provata su un caso finto malevolo e su un caso innocuo che
  gli somiglia apposta, per tenere bassi i falsi allarmi. I test coprono anche input ostili: file
  enormi o annidati, chiavi JSON doppie, `NaN`/`Infinity`, Unicode invisibile, numeri giganti.
- **Scudo in tempo reale.** Un server MCP finto (`tests/corpus/shield/fake_server.py`) si comporta
  male su richiesta. Può:
  - mandare rumore, risposte false e chiavi doppie;
  - mandare richieste dal server, messaggi enormi, strumenti avvelenati e istruzioni nascoste;
  - cambiare strumenti dopo l'approvazione (rug pull) o elencare lo stesso strumento due volte;
  - iniettare testo nei risultati, rifiutarsi di fermarsi o mandare Unicode non valido.

  I test controllano che lo Scudo blocchi, nasconda o scarti quello che deve e non lasci mai
  passare un messaggio quando il suo stesso controllo va in errore.
- **SDK ufficiale di MCP.** `tests/test_shield_sdk.py` fa passare dallo Scudo un client e un server
  costruiti con l'SDK Python ufficiale di MCP, con entrambe le versioni del protocollo
  (2025-11-25 e 2026-07-28). L'SDK serve solo ai test: Guardia non dipende da lui.
- **Promesse.** Niente codice di rete, un solo punto che avvia programmi, niente codice nascosto,
  pagina dell'app blindata: ogni promessa ha un test che fallisce se viene rotta. Vedi
  [AUDIT.md](AUDIT.md).
- **Registro e file firmati.** Vengono scoperte righe cancellate, cambiate o mancanti, un registro
  cancellato, un file delle regole cambiato e una memoria degli strumenti cancellata.
- **Configurazioni dei client.** Prima di ogni modifica viene salvata una copia di sicurezza. Le
  tue modifiche successive non vengono mai sovrascritte, e un file cambiato nel frattempo non
  viene toccato.

### Verifiche oltre i test automatici

- **Prove di mutazione.** Nei punti critici il codice è stato rotto apposta (per esempio togliendo
  il controllo che rifiuta un file delle regole non approvato, o saltando lo Scudo) per confermare
  che un test fallisca. Sono state fatte a mano sui controlli più importanti, non con uno strumento
  automatico.
- **Eseguibili Windows.** `guardia.exe` è stato guidato dal client dell'SDK ufficiale: protocollo
  2026-07-28, una chiamata normale passata, un tentativo di leggere una chiave SSH bloccato, e la
  finestra di conferma aperta dall'eseguibile che ha restituito la risposta. La riga di comando ha
  dato gli stessi risultati della versione Python su un PC reale, in sola lettura.
- **Eseguibili Windows della 0.2.3.** Costruiti senza gli strumenti di sviluppo. Lo zip della
  versione è stato estratto e ogni file segnato come scaricato da Internet, come fa Windows. Da
  lì, su una cartella utente finta: la riga di comando ha fatto la scansione, lo Scudo ha protetto
  un server finto e ha fatto passare una richiesta dalla voce protetta, la finestra di conferma si
  è aperta e ha bloccato da sola alla fine del conto alla rovescia, e l'app ha aperto la sua
  finestra e si è chiusa normalmente.
- **Finestra vera.** Su uno schermo reale, la finestra ingrandita ha coperto
  esattamente l'area di lavoro calcolata da Windows (2560×1386, barra delle applicazioni esclusa)
  ed è tornata allo stesso posto quando è stata ripristinata.
- **Velocità.** Lo Scudo aggiunge circa 0,06 ms per messaggio.

### Prima revisione (versione 0.2.0)

Prima della pubblicazione, una sessione separata di Claude Code ha rivisto tutto il progetto da
zero, senza il contesto della sessione che l'aveva scritto. Ha trovato **11 bug veri**. Per ognuno
prima un test che falliva, poi la correzione, poi lo stesso test che passa:

1. proteggere un server dall'app scriveva il programma dell'app invece di `guardia.exe`;
2. un percorso di rete (`\\server\cartella\…`) scritto in una configurazione poteva essere aperto
   dalla scansione;
3. un server poteva elencare due volte lo stesso strumento per far passare una copia cambiata;
4. modi alternativi di scrivere un percorso su Windows (`\\?\C:\…`, un punto finale, `::$DATA`)
   potevano aggirare le regole sui percorsi;
5. valori ostili (Unicode non valido, numeri giganti, date TOML) potevano far crashare la scansione
   o lo Scudo;
6. quattro difetti del registro, tra cui un registro cancellato segnalato come integro;
7. segreti scritti dentro argomenti più lunghi (`Authorization: Bearer …`) potevano finire nei
   rapporti;
8. «Togli protezione» nell'app agiva su tutti i server con lo stesso nome;
9. un file di test finto veniva cancellato da Windows Defender su PC puliti;
10. la scansione seguiva le giunzioni di Windows, con risultati doppi e scansioni lunghissime;
11. «ricorda per 10 minuti» non copriva le chiamate già in attesa.

Nello stesso passaggio la documentazione è stata corretta dove prometteva più di quello che il
codice fa.

### Seconda revisione (versione 0.2.2)

Dopo la prima pubblicazione, altre quattro sessioni di Claude Code hanno rivisto il progetto da
zero, ognuna su una parte e sempre con dati finti:

- **lo scanner su configurazioni realistiche** (percorsi con spazi, cartelle OneDrive,
  installazioni globali di npm e uv, profili di VS Code, file di Codex e Copilot): **20**
  problemi, soprattutto falsi allarmi;
- **lo Scudo e la riga di comando**, usati come farebbe un client vero: **19** problemi;
- **l'app desktop**, schermata per schermata: **21** problemi;
- **la documentazione**, letta come la leggerebbe un principiante: **14** problemi.

73 di questi 74 problemi sono corretti nella 0.2.2. Le correzioni al codice hanno i loro test
automatici (200 test nuovi dalla 0.2.1); l'app è stata controllata anche sulle schermate, in
tutte e due le lingue e con due dimensioni di finestra, e la documentazione a mano. L'unico
problema rimasto è un limite noto, scritto in [SECURITY.md](SECURITY.md): il codice che elenca
percorsi sensibili solo per bloccarli può essere segnalato come se li leggesse.

Tra le correzioni più importanti:

1. nomi come `GIT_AUTHOR_NAME` o `--auth-mode` venivano segnalati come segreti esposti, e testi
   normali di skill e strumenti come tool poisoning; lo Scudo predefinito nascondeva poi
   strumenti utili come `send_email`;
2. un percorso con uno spazio (per esempio `C:\Users\Mario Rossi\…`) spegneva l'analisi del
   codice, così un server avvelenato poteva sembrare pulito;
3. un solo carattere Unicode malformato in una configurazione o nel codice di un server fermava
   tutta la scansione;
4. qualsiasi programma chiamato `guardia.exe` contava come «protetto», e il suo comando vero non
   veniva analizzato;
5. lo Scudo poteva andare in crash quando il server si chiudeva per primo, e un limite di
   frequenza poteva bloccare il risultato di una chiamata già eseguita;
6. su Windows, fermare un server poteva lasciare attivi i programmi avviati da lui (come `node`
   avviato da `npx`);
7. una richiesta annullata dall'app AI mentre aspettava la tua conferma veniva eseguita lo
   stesso;
8. proteggere i server poteva fermarsi a metà su un file in sola lettura, senza lasciare niente
   con cui tornare indietro.

### Trovato dopo la pubblicazione

La versione 0.2.0 non partiva su un secondo portatile Windows quando veniva scaricata da GitHub:
Windows segna i file estratti da uno zip scaricato come «provenienti da Internet», e .NET si
rifiutava di caricare la libreria della finestra (`Failed to resolve Python.Runtime.Loader.Initialize`).
Il problema è stato riprodotto qui segnando allo stesso modo ogni file dello zip, corretto nella
0.2.1 con un file `.exe.config` accanto a ogni programma, e ricontrollato: con la correzione si aprono
sia l'app sia la finestra di conferma, senza torna lo stesso errore. Un test tiene la
configurazione nella build.

Nella versione 0.2.2 il bordo luminoso animato non compariva mai con la finestra ingrandita, che
da quella versione è il modo in cui l'app si apre, e con la finestra più piccola era solo una linea
di un pixel. La versione 0.2.3 lo sostituisce con un alone rosso morbido che scorre lungo il bordo
in ogni stato della finestra. È stato controllato sull'app vera, con foto della finestra a pochi
secondi di distanza, e un test lo tiene visibile.

### Non coperto

- **macOS e Linux**: il codice c'è, ma non è stato provato su computer reali.
- **Server MCP remoti (HTTP)**: lo Scudo non li supporta ancora, quindi non sono testati.
- **Malware vero**: mai usato, per scelta. I casi finti riproducono le tecniche, non i payload veri.
- **Firma digitale**: gli eseguibili non sono ancora firmati. Confrontali con `SHA256SUMS.txt`.

### Provalo tu

```powershell
uv sync --extra app
uv run pytest
uv run ruff check src tests scripts packaging
uv run mypy
```

GitHub esegue gli stessi controlli su un Windows pulito a ogni modifica
([`.github/workflows/tests.yml`](https://github.com/AlexanderPuglisi/GuardiaMCP/blob/main/.github/workflows/tests.yml)). Il risultato è il badge **Tests** in
cima al README.
