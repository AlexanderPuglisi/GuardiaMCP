# Lo Scudo di Guardia MCP

**by Alexander Puglisi** · [English version](SHIELD.md)

Lo Scudo è la parte di Guardia che lavora **mentre** l'AI usa i server MCP. L'analisi della v1
guarda i file e ti dice cosa c'è di rischioso; lo Scudo invece si mette in mezzo ai messaggi e può
**bloccarli, nasconderli o oscurarli** seguendo regole scritte da te.

> **Stato: anteprima di sviluppo (fase 2.1).** Le regole funzionano. La finestra per l'azione
> `chiedi` arriva nella fase 2.3; fino ad allora `chiedi` **blocca**. Il collegamento automatico
> dei client arriva nella fase 2.4: per ora la configurazione si modifica a mano (vedi sotto).

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
  "command": "C:\\Programmi\\GuardiaMCP\\guardia.exe",
  "args": ["scudo", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
}
```

Lo stesso schema vale per Claude Code, Cursor e VS Code. Nella fase 2.4 Guardia lo farà da solo,
con copia di sicurezza e comando per tornare indietro.

## Le regole in cinque minuti

```powershell
guardia scudo regole esempio --salva
guardia scudo regole verifica
guardia scudo regole prova --strumento read_file --argomenti '{"path": "~/.ssh/id_rsa"}'
guardia scudo regole approva
guardia scudo regole stato
```

1. **esempio --salva** crea il file delle regole con cinque regole utili per tutti.
2. Apri il file con un editor di testo e adattalo.
3. **verifica** controlla il file e ti dice riga per riga cosa non va, con un suggerimento
   quando sbagli a scrivere una chiave.
4. **prova** simula un messaggio e ti mostra quale decisione prenderebbe lo Scudo, senza
   avviare nessun server.
5. **approva** controlla il file, ti mostra le differenze rispetto all'ultima versione e lo
   **firma**. Gli Scudi già attivi usano le nuove regole entro un secondo.
6. **stato** ti dice se le regole sono attive o se lo Scudo è in blocco totale e perché.

I comandi esistono anche in inglese: `guardia shield rules verify | approve | test | example | status`.

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
| `chiedi` | `ask` | Serve la tua conferma (per ora **blocca**, la finestra arriva nella fase 2.3) |
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
  - gli indirizzi `file:///` diventano percorsi.

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
`shield_start` e `shield_stop` per ogni sessione, e `rules_approved` per ogni approvazione.

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
- `chiedi` blocca finché non arriva la finestra di conferma (fase 2.3).
- Su Windows, i programmi avviati a loro volta da un server (per esempio `node` avviato da `npx`)
  possono restare attivi se il server viene chiuso a forza.

Tutti i limiti di Guardia sono in [SECURITY.md](../SECURITY.md).
