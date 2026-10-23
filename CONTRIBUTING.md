# Contributing · Contribuire

[English](#english) · [Italiano](#italiano)

---

## English

Thank you for helping. Guardia MCP is free for everyone, forever, under the Apache 2.0 license.
By contributing you agree that your contribution is released under the same license.
There is no contributor agreement to sign.

### Rules that are never negotiable

1. **Free and private.** No paid edition, no accounts, no telemetry, no data sent off the PC.
   A change that adds network access to Guardia will not be accepted.
2. **Guardia never runs the code it analyzes.** No processes, `eval`/`exec`, dynamic imports or
   downloads. An automated test fails if one of these appears.
3. **Fake samples only.** Test cases are small fake MCP servers, fake descriptions and fake
   configurations written for the purpose. Never add real malware, real secrets, or material taken
   from other people's systems. Never test against systems you do not own.
4. **Clean code without comments.** Code should explain itself through names and structure.
   Explanations belong in `README.md` and `docs/`.
5. **Honesty.** Never claim a test passed if you did not run it. If a change has a limit, write it
   in `SECURITY.md`.

### Set up

You need Windows, macOS or Linux with [uv](https://docs.astral.sh/uv/) installed.

```powershell
cd C:\Progetti\GuardiaMCP
uv sync --extra app
uv run pytest
uv run ruff format src tests scripts packaging
uv run ruff check src tests scripts packaging
uv run mypy
```

All four checks must be green before a pull request.

### Where things are

| Folder | Contents |
|---|---|
| `src/guardia/inventory/` | finds MCP configurations and skills for each client |
| `src/guardia/extract/` | reads tools, code signals and dependencies from files, without running them |
| `src/guardia/scanner/` | the rules (`rules.py`) and the checks |
| `src/guardia/render/` | terminal, HTML, SARIF output and the rules guide |
| `src/guardia/app/` | desktop app (pywebview bridge, page, settings) |
| `src/guardia/shield/` | the real-time Shield: message checks, session, server process, proxy, TOML rules, engine, signed policy |
| `src/guardia/locales/` | every user-visible text, in `it.toml` and `en.toml` |
| `tests/corpus/` | fake samples: configurations, tool servers, code, skills |
| `scripts/` | build of the executables, demo GIF, icon |
| `packaging/` | PyInstaller spec and entry points |

### Adding or changing a rule

1. Add the rule to `src/guardia/scanner/rules.py` with a new code in the right family and a
   severity. Never reuse an old code for a different meaning.
2. Write `title`, `why` and `fix` in **both** `locales/it.toml` and `locales/en.toml`, in simple
   words. A test fails if the two languages do not have the same keys.
3. Add the detection in the matching check module.
4. Add **at least one malicious and one harmless** fake case to the corpus:
   `tests/corpus/config_cases.toml`, `tests/corpus/tools/`, `tests/corpus/code/` or
   `tests/corpus/skills/`. The harmless case should look similar on purpose, to prove the rule
   does not raise false alarms.
5. Regenerate the rules guide (a test fails if it is out of date):

   ```powershell
   uv run guardia rules --markdown --lang en -o docs/RULES.md
   uv run guardia regole --markdown --lingua it -o docs/REGOLE.md
   ```

6. Run all the checks above.

### Executables and demo GIF

Build tools (PyInstaller, Pillow) live in the separate `build` group and are pinned in `uv.lock`.

```powershell
uv run --group build --extra app python scripts\build_exe.py
uv run --group build --extra app python scripts\demo.py --lang en -o docs\demo-en.gif
uv run --group build --extra app python scripts\demo.py --lang it -o docs\demo-it.gif
uv run --group build --extra app python scripts\make_icon.py
```

`scripts/demo.py` creates a fake PC in a temporary folder (user "demo", fake servers and skills),
scans it with the real engine and photographs the real app page with Microsoft Edge in headless
mode. Never record a demo from your own PC: it would publish your paths and server names.

### Reporting a false alarm or a missed detection

Open an issue with:

- the rule code (for example `G02-001`) or the risk that was missed;
- a **fake, minimal** text or configuration that reproduces it. Remove names, paths and any secret;
- what you expected and what you got.

Security vulnerabilities in Guardia itself must **not** be reported in a public issue: follow
[SECURITY.md](SECURITY.md).

### Pull requests

Keep them small and focused, explain why the change is needed, and include tests that fail
without the change.

---

## Italiano

Grazie dell'aiuto. Guardia MCP è gratuito per tutti, per sempre, con licenza Apache 2.0.
Contribuendo accetti che il tuo contributo sia pubblicato con la stessa licenza.
Non c'è nessun accordo da firmare.

### Regole non negoziabili

1. **Gratuito e privato.** Nessuna versione a pagamento, nessun account, nessuna telemetria,
   nessun dato inviato fuori dal PC. Una modifica che fa collegare Guardia alla rete non verrà
   accettata.
2. **Guardia non esegue mai il codice che analizza.** Niente processi, `eval`/`exec`, import
   dinamici o download. Un test automatico fallisce se compare uno di questi.
3. **Solo esempi finti.** I casi di test sono piccoli server MCP finti, descrizioni finte e
   configurazioni finte scritte apposta. Non aggiungere mai malware vero, segreti veri o materiale
   preso da sistemi di altri. Non fare mai prove su sistemi che non sono tuoi.
4. **Codice pulito, senza commenti.** Il codice si spiega con i nomi e la struttura.
   Le spiegazioni vanno in `README.md` e in `docs/`.
5. **Onestà.** Non dire mai che un test è passato se non l'hai eseguito. Se una modifica ha un
   limite, scrivilo in `SECURITY.md`.

### Preparare l'ambiente

Serve Windows, macOS o Linux con [uv](https://docs.astral.sh/uv/) installato.

```powershell
cd C:\Progetti\GuardiaMCP
uv sync --extra app
uv run pytest
uv run ruff format src tests scripts packaging
uv run ruff check src tests scripts packaging
uv run mypy
```

Tutti e quattro i controlli devono essere verdi prima di una pull request.

### Dove si trovano le cose

| Cartella | Contenuto |
|---|---|
| `src/guardia/inventory/` | trova le configurazioni MCP e le skill di ogni client |
| `src/guardia/extract/` | legge strumenti, segnali nel codice e dipendenze dai file, senza eseguirli |
| `src/guardia/scanner/` | le regole (`rules.py`) e i controlli |
| `src/guardia/render/` | output per terminale, HTML, SARIF e la guida alle regole |
| `src/guardia/app/` | app desktop (ponte pywebview, pagina, impostazioni) |
| `src/guardia/shield/` | lo Scudo in tempo reale: controllo dei messaggi, sessione, processo del server, proxy, regole TOML, motore, regole firmate |
| `src/guardia/locales/` | tutti i testi visibili, in `it.toml` e `en.toml` |
| `tests/corpus/` | esempi finti: configurazioni, server con strumenti, codice, skill |
| `scripts/` | build degli eseguibili, GIF dimostrativa, icona |
| `packaging/` | file di PyInstaller e punti di avvio |

### Aggiungere o modificare una regola

1. Aggiungi la regola in `src/guardia/scanner/rules.py` con un codice nuovo nella famiglia giusta
   e un livello di gravità. Non riusare mai un vecchio codice con un significato diverso.
2. Scrivi `title`, `why` e `fix` in **entrambi** i file `locales/it.toml` e `locales/en.toml`,
   con parole semplici. Un test fallisce se le due lingue non hanno le stesse chiavi.
3. Aggiungi il controllo nel modulo giusto.
4. Aggiungi al corpus **almeno un caso malevolo e uno innocuo**, entrambi finti:
   `tests/corpus/config_cases.toml`, `tests/corpus/tools/`, `tests/corpus/code/` o
   `tests/corpus/skills/`. Il caso innocuo deve somigliare apposta a quello malevolo, per
   dimostrare che la regola non dà falsi allarmi.
5. Rigenera la guida alle regole (un test fallisce se non è aggiornata):

   ```powershell
   uv run guardia rules --markdown --lang en -o docs/RULES.md
   uv run guardia regole --markdown --lingua it -o docs/REGOLE.md
   ```

6. Esegui tutti i controlli qui sopra.

### Eseguibili e GIF dimostrativa

Gli strumenti di build (PyInstaller, Pillow) stanno nel gruppo separato `build` e hanno versioni
bloccate in `uv.lock`.

```powershell
uv run --group build --extra app python scripts\build_exe.py
uv run --group build --extra app python scripts\demo.py --lang en -o docs\demo-en.gif
uv run --group build --extra app python scripts\demo.py --lang it -o docs\demo-it.gif
uv run --group build --extra app python scripts\make_icon.py
```

`scripts/demo.py` crea un PC finto in una cartella temporanea (utente «demo», server e skill
finti), lo analizza con il motore vero e fotografa la pagina vera dell'app con Microsoft Edge in
modalità invisibile. Non registrare mai una demo dal tuo PC: pubblicheresti i tuoi percorsi e i
nomi dei tuoi server.

### Segnalare un falso allarme o un allarme mancato

Apri una issue con:

- il codice della regola (per esempio `G02-001`) o il rischio che non è stato visto;
- un testo o una configurazione **finta e minima** che riproduce il caso. Togli nomi, percorsi e
  qualsiasi segreto;
- cosa ti aspettavi e cosa hai ottenuto.

Le vulnerabilità di Guardia stesso **non** vanno segnalate in una issue pubblica: segui
[SECURITY.md](SECURITY.md).

### Pull request

Falle piccole e mirate, spiega perché la modifica serve e includi test che falliscono senza la
modifica.
