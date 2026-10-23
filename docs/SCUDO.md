# Lo Scudo di Guardia MCP

**by Alexander Puglisi** · [English version](SHIELD.md)

Lo Scudo è la parte di Guardia che lavora **mentre** l'AI usa i server MCP. L'analisi della v1
guarda i file e ti dice cosa c'è di rischioso; lo Scudo invece si mette in mezzo ai messaggi e può
**bloccarli, nasconderli o oscurarli** seguendo regole scritte da te.

> **Stato: versione 0.2.0.** Regole, protezioni di base, finestra di conferma, collegamento
> automatico dei client e vista «Scudo» nell'app. Provato con l'SDK Python ufficiale di MCP
> (protocolli 2025-11-25 e 2026-07-28).

## Come funziona, in 30 secondi

```
App AI (client)  ⇄  guardia scudo  ⇄  server MCP
                         │
                   regole.toml  +  registro
```

**Proxy** — un programma che si mette in mezzo tra due altri e passa i messaggi dall'uno all'altro.
Lo Scudo è un proxy: il client parla con lo Scudo, lo Scudo parla con il server.

Per ogni messaggio lo Scudo:

1. controlla che sia un messaggio MCP valido (altrimenti lo scarta);
2. guarda le tue regole e decide: consentire, registrare, oscurare, chiedere o bloccare;
3. scrive la decisione nel registro a prova di manomissione;
4. inoltra il messaggio, oppure risponde con un errore che spiega quale regola l'ha fermato.

Se qualcosa va storto (regole non approvate, registro non scrivibile, errore interno) lo Scudo
**blocca invece di lasciar passare**. Si chiama **fail-closed**: in caso di dubbio, porta chiusa.

## Avviare un server dietro lo Scudo

```powershell
guardia scudo --server github -- npx -y @modelcontextprotocol/server-github
```

Tutto quello che segue `--` è il comando del server, esattamente come lo scriveresti nella
configurazione del client. I messaggi di Guardia (regole attive, blocchi) vanno nel registro
degli errori del client, mai nel canale MCP.

Per proteggere un server in Claude Desktop, cambia la sua voce in `claude_desktop_config.json` da:

```json
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
```

a:

```json
{
  "command": "C:\\Users\\TUO-NOME\\GuardiaMCP\\guardia.exe",
  "args": ["scudo", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
}
```

Lo stesso schema vale per Claude Code, Cursor e VS Code, ma **non serve farlo a mano**: Guardia lo
fa per te.

### Collegare i server in automatico

```powershell
guardia scudo elenco
guardia scudo attiva --server github
guardia scudo attiva --server github --conferma
guardia scudo disattiva --server github --conferma
```

- **elenco** mostra tutti i server MCP del PC e, per ognuno, se è protetto dallo Scudo, se si può
  collegare in automatico o perché no.
- **attiva** senza `--conferma` mostra solo cosa farebbe; con `--conferma` salva una copia di
  sicurezza del file nella cartella `backup` di Guardia, modifica solo la voce di quel server e
  annota la voce originale. `--tutti` collega tutti i server collegabili.
- **disattiva** rimette la voce originale, ma solo se nel frattempo non l'hai cambiata tu.
- Le stesse azioni sono nella sezione **Scudo** dell'app, con una conferma prima di ogni modifica.

Prima di collegare un server **chiudi l'app AI**: alcune app riscrivono il proprio file di
configurazione e potrebbero cancellare la modifica. Se Guardia si accorge che il file è cambiato
mentre lavorava, non scrive nulla.

| Dove sta il server | Cosa fa Guardia |
|---|---|
| File JSON normale (Claude Desktop, Claude Code, Cursor, `mcp.json` di VS Code, Windsurf, Gemini, Copilot) | Collegamento automatico |
| File con commenti (per esempio `settings.json` di VS Code) o file TOML (Codex) | Ti mostra il testo esatto da incollare, per non toccare i tuoi commenti |
| Estensioni di Claude Desktop, plugin, configurazioni gestite dall'amministratore | Non collegabili: le gestiscono le app |
| Server remoti (HTTP) | Non ancora protetti dallo Scudo |

Un server collegato continua a essere analizzato dalla scansione della v1 con il suo **comando
originale**: la protezione non nasconde nulla all'analisi.

## Le regole in cinque minuti

**Dall'app**, senza terminale: sezione **Scudo** → **Crea le regole d'esempio** →
**Modifica le regole** → cambia il testo → **Salva e approva**. Guardia controlla il testo
prima di salvarlo: se c'è un errore ti mostra la riga e non salva niente.

**Da riga di comando:**

```powershell
guardia scudo regole esempio --salva
guardia scudo regole verifica
guardia scudo regole prova --strumento read_file --argomenti '{"path": "~/.ssh/id_rsa"}'
guardia scudo regole approva
guardia scudo regole stato
```

1. **esempio --salva** crea il file delle regole con cinque regole utili per tutti.
   Finché non lo approvi, i server protetti sono in **blocco totale** (il file non è ancora
   firmato): chiudi l'app AI mentre lo modifichi.
2. Apri il file con un editor di testo e adattalo.
3. **verifica** controlla il file e ti dice riga per riga cosa non va, con un suggerimento
   quando sbagli a scrivere una chiave.
4. **prova** simula un messaggio e ti mostra quale decisione prenderebbero **le tue regole**,
   senza avviare nessun server. Le protezioni di base non vengono simulate. In Windows PowerShell
   5.1 metti la barra davanti alle virgolette interne:
   `--argomenti '{\"path\": \"~/.ssh/id_rsa\"}'` (PowerShell 7 accetta la forma sopra).
5. **approva** controlla il file, ti mostra le differenze rispetto all'ultima versione e lo
   **firma**. Gli Scudi già attivi usano le nuove regole entro un secondo.
6. **stato** ti dice se le regole sono attive o se lo Scudo è in blocco totale e perché.

I comandi esistono anche in inglese: `guardia shield rules verify | approve | test | example | status`.
Il file d'esempio è in italiano quando la lingua è l'italiano (`--lingua it`).

## La finestra di conferma

Quando una regola o una protezione dice `chiedi`, lo Scudo apre una piccola finestra di Guardia,
sempre in primo piano, che mostra:

- quale server vuole fare cosa (strumento o richiesta);
- **perché** te lo chiede (la regola o la protezione);
- i dettagli della richiesta, con i segreti già oscurati;
- i pulsanti **Blocca** (già selezionato, per sicurezza) e **Consenti**, e la casella «ricorda la
  scelta per 10 minuti» per quello strumento;
- un conto alla rovescia: **se non rispondi entro 60 secondi, blocca**. Anche `Esc` e il cerchietto
  di chiusura bloccano.

Mentre aspetta la tua risposta, lo Scudo continua a far passare gli altri messaggi. La finestra è
un processo separato di Guardia che parla con lo Scudo su un canale privato: **l'AI e il server non
possono rispondere al posto tuo**. Se la finestra non si può mostrare, la richiesta viene bloccata.
Ogni risposta finisce nel registro.

`chiedi` vale per le **chiamate** e per le **richieste del server**. Su risultati ed elenchi non ha
senso chiedere (l'azione è già avvenuta o non è ancora stata richiesta): lì vale come `registra`.

## Le protezioni di base

Lo Scudo protegge anche **senza nessuna regola scritta da te**. Queste protezioni applicano in
tempo reale le regole della v1 che controllano descrizioni e schemi degli strumenti e istruzioni
del server.

| Protezione | Cosa fa | Predefinito | Valori |
|---|---|---|---|
| `strumenti_approvati` | La prima volta che vede un server ne memorizza gli strumenti. Se poi uno strumento **cambia** (rug pull) o **compare all'improvviso**, viene nascosto all'AI finché non lo approvi | `true` | `true`, `false` |
| `analisi` | Controlla la descrizione e lo schema di ogni strumento elencato e le istruzioni del server: nasconde gli strumenti e toglie le istruzioni con problemi da quel livello in su | `"alto"` | `"critico"`, `"alto"`, `"medio"`, `"spento"` |
| `risultati` | Cerca prompt injection e istruzioni nascoste nei risultati degli strumenti | `"avvisa"` | `"avvisa"`, `"blocca"`, `"spento"` |
| `segreti_in_uscita` | Un segreto (chiave, token) negli argomenti di una chiamata | `"chiedi"` | `"chiedi"`, `"blocca"`, `"registra"`, `"spento"` |
| `segreti_nei_risultati` | Segreti nei risultati: vengono sostituiti da `[REDACTED]` | `"oscura"` | `"oscura"`, `"spento"` |
| `richieste_credenziali` | Un server chiede password, OTP, chiavi, frasi di recupero o dati della carta | `"blocca"` | `"blocca"`, `"chiedi"`, `"registra"`, `"spento"` |

`avvisa` lascia passare il risultato ma lo segnala nel registro e nel log del client.

**Uno strumento nascosto non si può nemmeno chiamare**: se l'AI prova a usarlo (perché lo
ricordava da prima, o perché il client ha tenuto in memoria un vecchio elenco), lo Scudo blocca
la chiamata e spiega perché. Per lo stesso motivo blocca le chiamate a strumenti che **non ha mai
visto** in un elenco: un client normale chiede sempre l'elenco prima di usare uno strumento.

Le protezioni si allentano **solo** nel file delle regole, quindi solo con la tua approvazione
firmata. `verifica` mostra un avviso per ogni protezione allentata:

```toml
versione = 1

[protezioni]
risultati = "blocca"
segreti_in_uscita = "registra"
```

### Approvare gli strumenti nuovi o cambiati

```powershell
guardia scudo strumenti elenco
guardia scudo strumenti approva --server github
guardia scudo strumenti approva --server github --strumento create_issue
guardia scudo strumenti dimentica --server github
```

- **elenco** mostra, per ogni server, quanti strumenti sono approvati e quali sono in attesa, con il
  motivo (nuovo o cambiato) e un pezzo della loro impronta.
- **approva** approva tutti gli strumenti in attesa di un server, oppure solo quelli indicati.
- **dimentica** cancella la memoria di un server: alla prossima connessione gli strumenti verranno
  memorizzati di nuovo come se fosse la prima volta.

Dopo l'approvazione, riavvia la connessione del server nel client per vedere gli strumenti.

**Rug pull** — un server che era innocuo e cambia di nascosto dopo che ti sei fidato.
La memoria degli strumenti (`scudo-strumenti.json`) è **firmata**: se qualcuno la modifica o la
cancella, lo Scudo se ne accorge (anche grazie al registro) e nasconde tutti gli strumenti di quel
server finché non li approvi di nuovo.

## Dove sta il file e perché va approvato

Il file è `%LOCALAPPDATA%\GuardiaMCP\regole.toml`. Quando lo approvi, Guardia salva una **firma**
(`regole.firma`) fatta con la stessa chiave protetta da Windows DPAPI che firma il registro.

**Firma** — un codice calcolato dal contenuto del file con una chiave segreta. Se cambia anche una
sola lettera del file, la firma non corrisponde più.

Perché serve? Un server MCP malevolo è un programma che gira con il tuo utente: potrebbe provare a
riscrivere le regole per liberarsi. Se lo Scudo trova il file cambiato senza una nuova
approvazione, va in **blocco totale**: rifiuta ogni messaggio e spiega come sbloccarlo.

| Situazione | Cosa fa lo Scudo |
|---|---|
| Nessun file e nessuna approvazione | Lascia passare e registra le chiamate (comportamento predefinito) |
| File presente ma mai approvato | Blocco totale: «le regole non sono approvate» |
| File modificato dopo l'approvazione | Blocco totale: «il file è stato modificato» |
| File approvato poi cancellato | Blocco totale: «il file approvato è stato cancellato» |
| Chiave di firma non leggibile | Blocco totale: approva di nuovo le regole |

## Com'è fatto il file

```toml
versione = 1
predefinito = "consenti"

[[regola]]
nome = "Mai toccare le chiavi SSH"
azione = "blocca"
fase = "chiamata"
argomento.percorso = ["~/.ssh/**", "**/.ssh/**"]
```

- `versione` è sempre `1`.
- `predefinito` dice cosa fare quando nessuna regola corrisponde.
- Ogni `[[regola]]` ha un **nome**, un'**azione** e delle **condizioni**.
- Una regola scatta solo se **tutte** le sue condizioni sono vere; dentro una lista basta che
  **uno** dei valori corrisponda.

Ogni chiave ha un nome italiano e uno inglese, e li puoi mescolare. L'unica eccezione è
l'intestazione: in tutto il file usa `[[regola]]` oppure `[[rule]]`, non entrambe.

### Le chiavi

| Italiano | English | Cosa fa | Esempio |
|---|---|---|---|
| `versione` | `version` | Versione del formato, sempre 1 | `versione = 1` |
| `predefinito` | `default` | Azione quando nessuna regola corrisponde | `predefinito = "consenti"` |
| `regola` | `rule` | Una regola: `[[regola]]` | |
| `nome` | `name` | Nome della regola, compare negli errori e nel registro | `nome = "No SSH"` |
| `azione` | `action` | Cosa fare quando la regola scatta | `azione = "blocca"` |
| `attiva` | `enabled` | `false` per spegnere la regola senza cancellarla | `attiva = false` |
| `nota` | `note` | Un appunto per te, Guardia lo ignora | `nota = "aggiunta a ottobre"` |
| `server` | `server` | Nome del server (quello dato con `--server`) | `server = "github"` |
| `strumento` | `tool` | Nome dello strumento o del prompt | `strumento = ["delete_*"]` |
| `metodo` | `method` | Metodo MCP | `metodo = "resources/read"` |
| `fase` | `phase` | In quale momento vale la regola | `fase = "chiamata"` |
| `argomento` | `argument` | Condizioni sugli argomenti di una chiamata | `argomento.percorso = "~/.ssh/**"` |
| `campo` | `field` | Guarda solo questi argomenti | `argomento.campo = "url"` |
| `percorso` | `path` | Percorsi di file | `argomento.percorso = "**/.env"` |
| `host` | `host` | Indirizzi web da colpire | `argomento.host = "*.ngrok.io"` |
| `host_non_in` | `host_not_in` | Scatta per ogni indirizzo **fuori** da questa lista | `argomento.host_non_in = ["github.com"]` |
| `contiene` | `contains` | Parole o frasi, senza distinguere maiuscole | `argomento.contiene = "DROP TABLE"` |
| `regex` | `regex` | Espressioni regolari | `contenuto.regex = "\\d{16}"` |
| `contenuto` | `content` | Condizioni su tutto il testo del messaggio | `contenuto.segreti = true` |
| `segreti` | `secrets` | Chiavi e token riconosciuti (GitHub, GitLab, Slack, AWS, Google, OpenAI, Anthropic, JWT) | `contenuto.segreti = true` |
| `dimensione_max` | `max_size` | Scatta quando il messaggio supera questi byte | `contenuto.dimensione_max = 1000000` |
| `frequenza` | `rate` | Limite di chiamate nel tempo | `frequenza = { massimo = 30, secondi = 60 }` |
| `massimo` | `max` | Numero massimo nella finestra di tempo | |
| `secondi` | `seconds` | Durata della finestra di tempo | |
| `protezioni` | `protections` | Sezione che regola le protezioni di base | `[protezioni]` |
| `strumenti_approvati` | `approved_tools` | Memoria degli strumenti approvati | `strumenti_approvati = true` |
| `analisi` | `analysis` | Analisi in tempo reale di strumenti e istruzioni | `analisi = "alto"` |
| `risultati` | `results` | Controllo dei risultati | `risultati = "avvisa"` |
| `segreti_in_uscita` | `outgoing_secrets` | Segreti negli argomenti | `segreti_in_uscita = "chiedi"` |
| `segreti_nei_risultati` | `result_secrets` | Segreti nei risultati | `segreti_nei_risultati = "oscura"` |
| `richieste_credenziali` | `credential_requests` | Richieste di password e credenziali | `richieste_credenziali = "blocca"` |

### Le fasi

| Italiano | English | Quando |
|---|---|---|
| `chiamata` | `call` | L'AI chiede qualcosa al server: usare uno strumento, leggere una risorsa, chiedere un prompt |
| `risultato` | `result` | Il server risponde a una chiamata |
| `elenco` | `list` | Il server mostra l'elenco dei suoi strumenti: con `blocca` lo strumento viene **nascosto** all'AI |
| `richiesta_server` | `server_request` | Il server chiede qualcosa al client: sampling, domande all'utente (elicitation), anche nel nuovo schema a più passaggi |

Se non scrivi `fase`, la regola vale in tutte le fasi in cui le sue condizioni hanno senso.
Le condizioni su `argomento` valgono solo nella fase `chiamata`.

### Le azioni

| Italiano | English | Cosa succede |
|---|---|---|
| `consenti` | `allow` | Il messaggio passa |
| `registra` | `log` | Passa e viene scritto nel registro |
| `oscura` | `redact` | Passa, ma le parti che corrispondono diventano `[REDACTED]` |
| `chiedi` | `ask` | Si apre la finestra di conferma; senza risposta in 60 secondi **blocca** |
| `blocca` | `block` | Il messaggio non passa; chi l'ha inviato riceve un errore con il nome della regola |

**Se più regole scattano insieme, vince la più severa**: blocca > chiedi > oscura > registra >
consenti. L'ordine in cui le scrivi non conta. Quindi una regola `consenti` non può annullare una
regola `blocca`: per fare eccezioni usa `host_non_in` o condizioni più precise.

**Il predefinito** vale per chiamate, elenchi e richieste del server, ma **non per i risultati**:
se hai consentito una chiamata, il suo risultato passa (a meno che una regola esplicita dica
altro). Con `predefinito = "blocca"` ottieni una **lista bianca**: passa solo ciò che consenti.

## Come vengono confrontati i valori

- **Nomi** (server, strumento, metodo, host): `*` vale qualsiasi testo, `?` un carattere.
  Maiuscole e minuscole non contano: `delete_*` colpisce anche `Delete_Repo`.
- **Percorsi**: prima del confronto Guardia li normalizza.
  - `~`, `%USERPROFILE%` e `$HOME` diventano la tua cartella utente;
  - le barre `\` diventano `/`;
  - i passaggi `..` vengono risolti;
  - gli indirizzi `file:///` diventano percorsi;
  - le scritture Windows che aprono lo stesso file diventano il percorso normale: `\\?\C:\…`,
    `\\.\C:\…`, `\\localhost\C$\…`, i punti finali (`.ssh.`) e i flussi (`.env::$DATA`).

  `~/progetti/../.ssh/id_rsa` diventa quindi `~/.ssh/id_rsa`. Negli schemi, `*` non attraversa le
  cartelle mentre `**` sì: `**/.env` colpisce `.env` in qualsiasi cartella.
- **Percorsi relativi** (come `../../.ssh/id_rsa`) non si possono ricondurre alla cartella utente:
  per prenderli usa schemi che iniziano con `**/`, come `**/.ssh/**`.
- **Host**: Guardia cerca gli indirizzi web (`https://…`, `wss://…`, `ftp://…`) dentro gli
  argomenti e ne estrae il nome. `*.github.com` colpisce `api.github.com` ma non `github.com`:
  se li vuoi entrambi, scrivili tutti e due.
- **Segreti**: riconosce i formati di chiave più comuni. Un segreto in un formato insolito può
  sfuggire.

**Glob** — uno schema con `*` e `?` per dire «qualsiasi nome che assomiglia a questo».
**Espressione regolare (regex)** — un linguaggio più potente per descrivere testi, per esperti.
Una regex scritta male può essere lenta: preferisci `contiene` quando basta.

## Ricette

Blocca un server intero:

```toml
[[regola]]
nome = "Server sospeso"
server = "vecchio-server"
azione = "blocca"
```

Chiedi conferma prima che GitHub scriva qualcosa:

```toml
[[regola]]
nome = "GitHub: chiedi prima di scrivere"
server = "github"
strumento = ["create_*", "delete_*", "push_*", "merge_*", "update_*"]
azione = "chiedi"
```

I dati possono uscire solo verso indirizzi che conosci:

```toml
[[regola]]
nome = "Solo indirizzi noti"
fase = "chiamata"
azione = "blocca"
argomento.host_non_in = ["github.com", "*.github.com", "api.openai.com"]
```

Lista bianca: passa solo ciò che consenti esplicitamente. Gli strumenti che non consenti vengono
anche nascosti dall'elenco, perché il predefinito vale anche nella fase `elenco`.

```toml
versione = 1
predefinito = "blocca"

[[regola]]
nome = "Avvio e elenchi"
fase = "chiamata"
metodo = ["initialize", "tools/list", "ping", "server/discover"]
azione = "consenti"

[[regola]]
nome = "Strumenti di sola lettura"
strumento = ["read_*", "list_*", "search_*", "get_*"]
azione = "consenti"
```

Nascondi gli strumenti la cui descrizione dà ordini all'AI:

```toml
[[regola]]
nome = "Descrizioni sospette"
fase = "elenco"
azione = "blocca"
contenuto.contiene = ["ignore previous instructions", "<important>", "do not tell the user"]
```

Oscura nomi e numeri di carta nei risultati:

```toml
[[regola]]
nome = "Dati personali nei risultati"
fase = "risultato"
azione = "oscura"
contenuto.contiene = ["Mario Rossi"]
contenuto.regex = ["\\b(?:\\d[ -]?){13,16}\\b"]
```

Nessun server può chiederti una password:

```toml
[[regola]]
nome = "Nessuna richiesta di password"
fase = "richiesta_server"
azione = "blocca"
contenuto.contiene = ["password", "passcode", "codice otp"]
```

Al massimo 30 chiamate al minuto per server:

```toml
[[regola]]
nome = "Freno alle chiamate"
fase = "chiamata"
metodo = "tools/call"
azione = "blocca"
frequenza = { massimo = 30, secondi = 60 }
```

## Cosa finisce nel registro

Per ogni chiamata a strumenti, risorse e prompt, e per **ogni** decisione diversa da «consenti»,
il registro riceve un evento `shield_decision` con: server, fase, metodo, strumento, azione, nomi
delle regole e un'**impronta** del messaggio.

**Impronta** — un codice (SHA-256) calcolato dal messaggio. Permette di dimostrare quale messaggio
era senza conservarne il contenuto.

Gli argomenti e i risultati **non** vengono mai scritti nel registro. Ci sono anche gli eventi
`shield_start` e `shield_stop` per ogni sessione, `rules_approved` per ogni approvazione delle
regole, e `tools_pinned`, `tools_pending`, `tools_approved`, `tools_forgotten` per la memoria degli
strumenti, e `shield_enabled`, `shield_disabled` quando Guardia collega o scollega un server.

## Cosa vede l'AI quando un messaggio è bloccato

Il client riceve un errore MCP con codice `-32010` e un testo come:

> Bloccato da Guardia MCP Scudo. Regola: «Mai toccare le chiavi SSH».

Così sia tu sia l'AI capite cosa è successo e perché.

## Limiti onesti

- Lo Scudo vede **solo i messaggi MCP**. Un server malevolo resta un programma sul tuo PC e può
  leggere i tuoi file direttamente, senza passare dall'AI. Lo Scudo non sostituisce un antivirus
  né l'attenzione a quali server installi.
- Le regole sono **schemi**, non comprensione: un testo scritto apposta per aggirarle può
  riuscirci. Le regole di esempio sono un punto di partenza, non una garanzia.
- La firma delle regole ferma le modifiche fatte di nascosto, ma chi riesce a eseguire codice con
  il tuo utente di Windows può usare anche la chiave di firma.
- Per ora lo Scudo protegge solo i server locali (stdio). I server remoti HTTP richiedono che
  Guardia inoltri traffico di rete: è una decisione separata.
- Una persona che usa il tuo PC può rispondere alla finestra di conferma: lo Scudo non sa chi
  clicca.
- La memoria degli strumenti si fida della **prima volta**: un server già malevolo al primo
  incontro viene giudicato solo dall'analisi e dalle tue regole.
- Il controllo dei risultati guarda il primo milione di caratteri di ogni risultato.
- Le richieste di credenziali vengono riconosciute da parole chiave in italiano e inglese: una
  richiesta formulata in modo diverso può sfuggire.
- Dopo che approvi uno strumento, il client lo vede solo quando richiede di nuovo l'elenco.
- Con Claude Desktop installato dal Microsoft Store, se il primo a creare la cartella dei dati
  di Guardia è lo Scudo avviato da Claude, Windows la mette nella cartella privata di Claude
  (`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Local\GuardiaMCP`) e l'app non la vede.
  Apri Guardia una volta dalla sua icona prima di proteggere i server.
- Un'app AI che riscrive il proprio file di configurazione può togliere il collegamento allo
  Scudo: `guardia scudo elenco` mostra sempre lo stato attuale.
- Su Windows, i programmi avviati a loro volta da un server (per esempio `node` avviato da `npx`)
  possono restare attivi se il server viene chiuso a forza.

Tutti i limiti di Guardia sono in [SECURITY.md](../SECURITY.md).
