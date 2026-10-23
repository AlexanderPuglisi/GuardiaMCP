# How Guardia was tested · Come è stato testato Guardia

[English](#english) · [Italiano](#italiano)

---

## English

A security tool is only worth what its tests prove. This page lists what was actually run on
version 0.2.1, how, and what is **not** covered. Nothing here was run against real malware or
anyone else's systems: every "attack" is a fake server or fake file written for the purpose.

### In numbers

| | |
|---|---|
| Automated tests | **645**, all passing (`uv run pytest`) |
| Test files | 27 |
| Fake samples (configurations, servers, code, skills) | 84 files in `tests/corpus/` |
| Static rules, each with at least one malicious and one harmless fake case | 88 |
| Lint and types | `ruff` and `mypy --strict`: no issues |

### What the tests cover

- **Scanner.** Every one of the 88 rules is tested on a malicious fake case and on a harmless case
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
- **Real window.** On a real screen, the maximized window covered exactly the work area
  computed by Windows (2560×1386, taskbar excluded) and went back to the same place when restored.
- **Speed.** The Shield adds about 0.06 ms per message.

### Independent review

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

### Found after release

Version 0.2.0 did not start on a second Windows laptop when downloaded from GitHub: Windows marks
files extracted from a downloaded zip as "from the Internet", and .NET refused to load the window
library (`Failed to resolve Python.Runtime.Loader.Initialize`). The problem was reproduced here by
marking every file of the release zip the same way, fixed in 0.2.1 with a `.exe.config` next to
each program, and checked again: with the fix both the app and the confirmation window open, without
it the same error comes back. A test keeps the configuration in the build.

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

---

## Italiano

Uno strumento di sicurezza vale quanto dimostrano i suoi test. Qui c'è cosa è stato eseguito
davvero sulla versione 0.2.1, come, e cosa **non** è coperto. Niente è stato provato con malware
vero o su sistemi di altri: ogni «attacco» è un server finto o un file finto scritto apposta.

### In numeri

| | |
|---|---|
| Test automatici | **645**, tutti passati (`uv run pytest`) |
| File di test | 27 |
| Esempi finti (configurazioni, server, codice, skill) | 84 file in `tests/corpus/` |
| Regole statiche, ognuna con almeno un caso finto malevolo e uno innocuo | 88 |
| Stile e tipi | `ruff` e `mypy --strict`: nessun problema |

### Cosa coprono i test

- **Scanner.** Ognuna delle 88 regole è provata su un caso finto malevolo e su un caso innocuo che
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
- **Finestra vera.** Su uno schermo reale, la finestra ingrandita ha coperto
  esattamente l'area di lavoro calcolata da Windows (2560×1386, barra delle applicazioni esclusa)
  ed è tornata allo stesso posto quando è stata ripristinata.
- **Velocità.** Lo Scudo aggiunge circa 0,06 ms per messaggio.

### Revisione indipendente

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

### Trovato dopo la pubblicazione

La versione 0.2.0 non partiva su un secondo portatile Windows quando veniva scaricata da GitHub:
Windows segna i file estratti da uno zip scaricato come «provenienti da Internet», e .NET si
rifiutava di caricare la libreria della finestra (`Failed to resolve Python.Runtime.Loader.Initialize`).
Il problema è stato riprodotto qui segnando allo stesso modo ogni file dello zip, corretto nella
0.2.1 con un file `.exe.config` accanto a ogni programma, e ricontrollato: con la correzione si aprono
sia l'app sia la finestra di conferma, senza torna lo stesso errore. Un test tiene la
configurazione nella build.

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
