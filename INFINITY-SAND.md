# INFINITY-SAND

[Italiano](#italiano) · [English](#english)

---

## Italiano

### Cos'è INFINITY-SAND

INFINITY-SAND è uno standard di sicurezza con un nome. Ha due facce.

1. **Un'etichetta.** Nei progetti e nei documenti si scrive «regola INFINITY-SAND applicata».
   Chi è fuori non sa cosa voglia dire; per chi lavora al progetto rimanda alla lista di regole
   qui sotto. È un marchio di qualità, non un meccanismo.
2. **La sostanza.** Cinque pilastri e due «MAI». Questi sì che contano.

Un'onestà da mettere subito in chiaro: la forza non è nel nome, è nel fatto che le regole siano
davvero applicate nel codice. L'etichetta da sola non esegue niente. Per questo, sotto, ogni
pilastro è messo a confronto con quello che GuardiaMCP fa **davvero**, con il test che lo prova e
con i limiti detti senza giri di parole.

### I cinque pilastri

1. **Segreti al loro posto.** Le chiavi e le password stanno dove devono stare (il file dei segreti
   sul computer), mai scritte nel codice né passate al browser.
2. **Superficie chiusa.** Si espone il meno possibile: niente porte aperte inutili, accesso ridotto
   all'essenziale.
3. **Opacità + esca.** Il sistema non rivela com'è fatto dentro, e tiene un'esca (canary): se l'esca
   viene toccata, sai che qualcuno ha curiosato.
4. **Copie cifrate che ruotano.** Backup cifrati, si tengono gli ultimi e si cancellano i vecchi, con
   almeno una copia fuori dal computer.
5. **Osservare e annotare.** Un rilevatore che guarda e scrive cosa succede, in modo verificabile.

### I due MAI

- **MAI auto-distruzione.** Niente «dead-man switch», niente cancellazione automatica di sé stessi:
  il rischio di distruggere i propri dati per sbaglio è più grande del vantaggio.
- **MAI triturazione continua del codice.** Niente offuscamento o rimescolamento perpetuo: è fatica
  che protegge una cassaforte vuota e rende il codice invérificabile. Un codice leggibile è un
  valore.

### Come GuardiaMCP applica INFINITY-SAND, oggi

I pilastri nascono per un sistema con un server. GuardiaMCP è un programma locale senza rete, quindi
alcuni pilastri si leggono adattati al suo contesto. Qui sotto, cosa fa il codice davvero — niente
promesse che non siano provate da un test che puoi lanciare con `uv run pytest`.

| Pilastro | Cosa fa GuardiaMCP davvero | Il test che lo prova | Stato |
|---|---|---|---|
| **1 · Segreti al loro posto** | La sua unica chiave segreta (quella del registro) è protetta con DPAPI e salvata solo sul tuo PC. I segreti trovati nelle configurazioni non vengono mai copiati né salvati: solo segnalati e oscurati con `[REDACTED]`. La pagina dell'app riceve solo testo, mai codice, con CSP rigida. | `test_self_defense.py`, `test_app.py::test_page_has_strict_csp_with_matching_hashes` | ✅ applicato |
| **2 · Superficie chiusa** | Nessun codice di rete: GuardiaMCP non apre, non ascolta e non chiama nessuna connessione. Un solo punto avvia programmi (`shield/process.py`), mai tramite shell. Niente `eval`/`exec`. | `test_self_defense.py::test_guardia_has_no_network_code`, `test_tool_corpus.py` | ✅ per costruzione |
| **3 · Opacità + esca** | Oltre al registro firmato, ora c'è un vero canary: un segreto-trappola (`guardia esca crea`) che pianti dove un server curioso guarderebbe. Se un server MCP lo legge e lo rimanda, lo Scudo lo vede nel traffico, **blocca** e lo scrive nel registro. | `test_canary.py`, `test_shield_canary.py` | ✅ applicato |
| **4 · Copie cifrate che ruotano** | `guardia copia crea` fa uno snapshot **cifrato** (DPAPI) di registro, regole ed esche, tiene gli ultimi N e cancella i vecchi. La copia fuori dal PC resta un passo manuale (copiarlo su una chiavetta), per scelta: niente rete. | `test_backup.py` | ✅ applicato |
| **5 · Osservare e annotare** | Lo scanner e il registro osservano e annotano in modo verificabile (catena SHA-256 + firma HMAC). In più lo Scudo blocca in tempo reale: nel dubbio blocca (fail-closed). Osserva dove serve, blocca dove serve, e scrive sempre cosa è successo. | `test_ledger_reports.py`, `test_shield.py` | ✅ e oltre |

### I due MAI in GuardiaMCP

- **Auto-distruzione: assente, per scelta.** GuardiaMCP non si cancella mai da solo, non ha né
  dead-man switch né self-destruct. Questo risponde anche a un'idea che era venuta in mente: un
  dead-man switch sarebbe contro la dottrina stessa. La regola ha già deciso: no.
- **Triturazione continua: assente, per scelta.** Il codice è leggibile e verificabile. Chiunque può
  smontarlo (vedi [AUDIT.md](AUDIT.md)); è proprio questo che lo rende affidabile.

### In una riga

Dalla 0.3.0 GuardiaMCP applica tutti e cinque i pilastri e rispetta entrambi i MAI. L'unico passo
manuale, per scelta, è portare la copia cifrata fuori dal PC (niente rete, mai). Questo documento
viene aggiornato quando lo stato cambia — e mai prima.

I limiti veri e completi sono in [SECURITY.md](SECURITY.md).

— Alexander

---

## English

### What INFINITY-SAND is

INFINITY-SAND is a security standard with a name. It has two sides.

1. **A label.** Across projects and documents you write "INFINITY-SAND rule applied". Outsiders do
   not know what it means; for whoever works on the project it points to the list of rules below.
   It is a mark of quality, not a mechanism.
2. **The substance.** Five pillars and two "NEVERs". These are what count.

One honesty up front: the strength is not in the name, it is in the rules being actually applied in
the code. The label on its own executes nothing. That is why, below, each pillar is set against what
GuardiaMCP **really** does, with the test that proves it and the limits stated plainly.

### The five pillars

1. **Secrets in their place.** Keys and passwords live where they belong (the secrets file on the
   computer), never written in the code nor handed to the browser.
2. **Closed surface.** Expose as little as possible: no needless open ports, access cut to the
   essentials.
3. **Opacity + decoy.** The system does not reveal how it is built inside, and keeps a decoy
   (canary): if the decoy is touched, you know someone went looking.
4. **Encrypted backups that rotate.** Encrypted backups, keep the latest and delete the old ones,
   with at least one copy off the computer.
5. **Observe and record.** A detector that watches and writes down what happens, verifiably.

### The two NEVERs

- **NEVER self-destruction.** No dead-man switch, no automatic self-deletion: the risk of destroying
  your own data by mistake is larger than the benefit.
- **NEVER continuous shredding of the code.** No perpetual obfuscation or reshuffling: it is effort
  that guards an empty safe and makes the code unverifiable. Readable code is an asset.

### How GuardiaMCP applies INFINITY-SAND, today

The pillars were conceived for a system with a server. GuardiaMCP is a local program with no
network, so some pillars read adapted to its context. Below is what the code really does — no
promise that is not backed by a test you can run with `uv run pytest`.

| Pillar | What GuardiaMCP really does | The test that proves it | Status |
|---|---|---|---|
| **1 · Secrets in their place** | Its one secret key (the ledger's) is protected with DPAPI and kept only on your PC. Secrets found in configurations are never copied or stored: only reported and masked with `[REDACTED]`. The app page receives only text, never code, under a strict CSP. | `test_self_defense.py`, `test_app.py::test_page_has_strict_csp_with_matching_hashes` | ✅ applied |
| **2 · Closed surface** | No network code: GuardiaMCP opens, listens to and calls no connection. A single place starts programs (`shield/process.py`), never through a shell. No `eval`/`exec`. | `test_self_defense.py::test_guardia_has_no_network_code`, `test_tool_corpus.py` | ✅ by design |
| **3 · Opacity + decoy** | On top of the signed ledger there is now a real canary: a trap secret (`guardia canary create`) you plant where a curious server would look. If an MCP server reads it and sends it back, the Shield sees it in the traffic, **blocks** and writes it in the ledger. | `test_canary.py`, `test_shield_canary.py` | ✅ applied |
| **4 · Encrypted rotating backups** | `guardia backup create` makes an **encrypted** (DPAPI) snapshot of the ledger, rules and canaries, keeps the latest N and deletes the old ones. The off-PC copy stays a manual step (copy it to a USB stick), on purpose: no network. | `test_backup.py` | ✅ applied |
| **5 · Observe and record** | The scanner and the ledger observe and record verifiably (SHA-256 chain + HMAC signature). On top, the Shield blocks in real time: when in doubt it blocks (fail-closed). It observes where needed, blocks where needed, and always writes down what happened. | `test_ledger_reports.py`, `test_shield.py` | ✅ and beyond |

### The two NEVERs in GuardiaMCP

- **Self-destruction: absent, on purpose.** GuardiaMCP never deletes itself, has no dead-man switch
  and no self-destruct. This also answers an idea that had come up: a dead-man switch would be
  against the doctrine itself. The rule already decided: no.
- **Continuous shredding: absent, on purpose.** The code is readable and verifiable. Anyone can take
  it apart (see [AUDIT.md](AUDIT.md)); that is exactly what makes it trustworthy.

### In one line

From 0.3.0 GuardiaMCP applies all five pillars and respects both NEVERs. The only manual step, on
purpose, is carrying the encrypted copy off the PC (no network, ever). This document is updated when
the status changes — and never before.

The real, complete limits are in [SECURITY.md](SECURITY.md).

— Alexander
