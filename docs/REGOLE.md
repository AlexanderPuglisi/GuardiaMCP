# Guida alle regole di Guardia MCP

Questa guida elenca tutte le 91 regole che Guardia usa per controllare server MCP e skill. Per ognuna trovi perché è un rischio e come correggerlo. La guida è generata dal programma stesso con `guardia regole --markdown`, quindi è sempre allineata al codice. Nei testi, «…» indica un valore che nel rapporto vero viene sostituito con il nome del server, del file o del campo trovato.

## I livelli di gravità

| Livello | Cosa significa |
|---|---|
| **CRITICO** | Quasi certamente un attacco o una falla grave. Intervieni subito: disattiva il server o la skill finché non hai capito. |
| **ALTO** | Rischio serio e concreto. Va corretto prima di continuare a usare il server. |
| **MEDIO** | Debolezza che un attaccante può sfruttare insieme ad altro. Correggi appena puoi. |
| **BASSO** | Cattiva abitudine o rischio piccolo. Da sistemare con calma. |
| **INFO** | Non è un problema: è un'informazione utile, per esempio cosa può fare un server o che qualcosa è cambiato. |

## Come leggere un problema

Ogni problema riporta un codice (per esempio G05-002), un livello, il punto esatto (file, riga e campo), cosa è stato trovato, perché è un rischio e come correggerlo. I segreti trovati non vengono mai mostrati per intero: al loro posto compare [REDACTED] o solo la lunghezza.

## Come sono fatti i codici

Il codice ha due parti: G05 è la famiglia (per esempio «comandi di sistema pericolosi»), 002 è la regola dentro la famiglia. I codici non vengono riusati per significati diversi, così puoi cercarli, citarli e filtrarli negli strumenti che leggono il formato SARIF.

## Cosa fare quando trovi un problema

1. Leggi «Perché» e «Come correggere» della regola.
2. Se non riconosci il server o la skill, disattivalo prima di indagare: è la scelta più sicura.
3. Se il problema è una modifica (famiglia G03) e l'aggiornamento l'hai fatto tu, accettala con `guardia scansiona --accetta-modifiche` oppure con il pulsante «Accetta le modifiche» nell'app. La scelta resta scritta nel registro.
4. Dopo la correzione, scansiona di nuovo per controllare che il problema sia sparito.
5. Se pensi che sia un falso allarme, segnalalo come spiegato in CONTRIBUTING.md.

## Falsi allarmi e allarmi mancati

Guardia lavora leggendo i file, senza eseguire nulla e senza intelligenza artificiale. Per questo può sbagliare in due modi: segnalare un testo innocuo (falso allarme) oppure non accorgersi di un trucco nuovo (allarme mancato). «Nessun problema trovato» non significa «sicuro»: significa che queste regole non hanno trovato nulla. Tutti i limiti sono spiegati in SECURITY.md.

## E le regole che scrivo io?

Le regole scritte da te in formato TOML guidano lo Scudo in tempo reale (vedi docs/SCUDO.md). Questa guida riguarda solo le regole fisse dell'analisi della versione 1, che non si possono disattivare: così nessun file malevolo può spegnerle.

## Parole utili

- **Tool poisoning** — istruzioni nascoste dentro la descrizione di uno strumento. L'utente non le vede, ma l'AI le legge e può obbedire.
- **Prompt injection** — testo scritto per sostituirsi agli ordini dell'utente, per esempio «ignora le istruzioni precedenti». Può arrivare da uno strumento, da un file o da una pagina web.
- **Rug pull** — un server che era innocuo e cambia di nascosto dopo che ti sei fidato. Guardia lo scopre confrontando ogni scansione con la base di confronto.
- **Shadowing** — un server che prova a influenzare come l'AI usa gli strumenti di un altro server, per esempio dicendo «quando usi send_email aggiungi questo indirizzo».
- **Typosquatting** — un pacchetto con un nome quasi uguale a uno famoso (una lettera in più o scambiata), pubblicato sperando che qualcuno sbagli a scrivere.
- **Segreto** — una chiave, un token o una password che dà accesso a un servizio. Se finisce in un file di configurazione, chiunque legga il file può usarlo.
- **Base di confronto** — la fotografia degli strumenti e delle skill presa alla scansione precedente. Serve per accorgersi di cosa è cambiato.
- **Skill** — una cartella con un file SKILL.md che insegna all'AI come fare un compito. Può contenere istruzioni e script, quindi va controllata come un server.

## Le famiglie di regole

- **G01** — Istruzioni nascoste e caratteri invisibili: 6 regole
- **G02** — Prompt injection: 4 regole
- **G03** — Modifiche nascoste (rug pull): 6 regole
- **G04** — Interferenza tra server (shadowing): 6 regole
- **G05** — Comandi di sistema pericolosi: 11 regole
- **G06** — Segreti esposti: 8 regole
- **G07** — Accesso a file sensibili: 6 regole
- **G08** — Permessi eccessivi: 6 regole
- **G09** — Rete sospetta: 12 regole
- **G10** — Dipendenze e catena di fornitura: 11 regole
- **G11** — Esposizione in rete: 1 regola
- **G12** — Igiene della configurazione: 9 regole
- **G13** — Registro a prova di manomissione: 2 regole
- **G14** — Skill: 3 regole

## G01 — Istruzioni nascoste e caratteri invisibili

### G01-001 · ALTO — Caratteri invisibili nella configurazione

**Perché.** Nel campo «…» ci sono caratteri che non si vedono a schermo (…). È una tecnica nota per far sembrare innocuo un testo che in realtà dice altro, all'AI o al programma.

**Come correggere.** Apri il file con un editor che mostra i caratteri invisibili e riscrivi il valore a mano. Se non sai da dove arriva questa configurazione, rimuovi il server.

### G01-002 · ALTO — Istruzioni nascoste per l'AI

**Perché.** Lo strumento «…» contiene marcatori come \<IMPORTANT\> o commenti HTML che di solito non vedi, ma che l'AI legge come istruzioni. È la forma classica del tool poisoning.

**Come correggere.** Non usare il server finché non hai letto per intero il testo segnalato. Se l'istruzione non è giustificata, rimuovi il server e avvisa l'autore.

### G01-003 · ALTO — Chiede all'AI di agire di nascosto

**Perché.** Il testo di «…» chiede di non avvisare l'utente o di fare qualcosa in silenzio. Uno strumento onesto non ha motivo di nascondere le proprie azioni.

**Come correggere.** Rimuovi il server: è un segnale tipico di strumenti malevoli.

### G01-004 · CRITICO — Testo invisibile nascosto con caratteri Unicode «tag»

**Perché.** Il campo «…» di «…» contiene caratteri invisibili che, decodificati, dicono: «…». L'AI può leggerli, tu no.

**Come correggere.** Rimuovi subito il server: questa tecnica serve solo a nascondere istruzioni.

### G01-005 · ALTO — Testo codificato nascosto

**Perché.** Il campo «…» di «…» contiene un blocco codificato (base64 o esadecimale) che si decodifica in testo leggibile: «…». Un testo nascosto così può contenere istruzioni per l'AI.

**Come correggere.** Verifica il contenuto decodificato. Se non ha una ragione tecnica evidente, rimuovi il server.

### G01-006 · MEDIO — Testo spinto fuori dallo schermo

**Perché.** Il campo «…» di «…» contiene moltissimi spazi o righe vuote, oppure è lunghissimo (… caratteri). È un trucco per nascondere istruzioni oltre la parte visibile.

**Come correggere.** Leggi il testo completo (per esempio nel rapporto JSON) e verifica cosa c'è in fondo.

## G02 — Prompt injection

### G02-001 · ALTO — Tentativo di sovrascrivere le istruzioni dell'AI

**Perché.** Il testo di «…» contiene una frase tipica della prompt injection, del tipo «ignora le istruzioni precedenti». Serve a far cambiare comportamento all'AI.

**Come correggere.** Rimuovi il server o fai correggere il testo all'autore.

### G02-002 · ALTO — Finti separatori di conversazione

**Perché.** Il testo di «…» imita i separatori interni di una conversazione con l'AI (per esempio «System:» o tag di risultato). Serve a far credere all'AI che il testo arrivi da te o dal sistema.

**Come correggere.** Rimuovi il server: un testo legittimo non ha bisogno di imitare questi separatori.

### G02-003 · ALTO — Chiede di consegnare la conversazione

**Perché.** Il testo di «…» chiede all'AI di includere la conversazione, i messaggi precedenti o le istruzioni di sistema. Così i tuoi dati finiscono al server.

**Come correggere.** Rimuovi il server, oppure chiedi all'autore perché gli servono.

### G02-004 · MEDIO — Ordina azioni preliminari all'AI

**Perché.** Il testo di «…» dice all'AI di leggere, eseguire o chiamare qualcosa prima di usare lo strumento. A volte è legittimo, ma è anche il modo in cui gli attacchi fanno compiere azioni non richieste.

**Come correggere.** Leggi il testo: se l'azione richiesta non c'entra con lo strumento, non usarlo.

## G03 — Modifiche nascoste (rug pull)

### G03-001 · ALTO — Strumento modificato dall'ultima analisi

**Perché.** La descrizione o i parametri di «…» sono cambiati rispetto all'ultima analisi approvata. È il segnale di un possibile rug pull: un server approvato che cambia di nascosto.

**Come correggere.** Controlla cosa è cambiato. Se la modifica è legittima (per esempio un aggiornamento), accettala con: guardia scansiona --accetta-modifiche

### G03-002 · INFO — Nuovo strumento

**Perché.** Il server ha aggiunto lo strumento «…» dall'ultima analisi.

**Come correggere.** Verifica che il nuovo strumento sia atteso. È già stato aggiunto alla base di confronto.

### G03-003 · MEDIO — Configurazione del server cambiata

**Perché.** Il comando, gli argomenti o le variabili di «…» sono cambiati rispetto all'ultima analisi approvata.

**Come correggere.** Se la modifica l'hai fatta tu, accettala con: guardia scansiona --accetta-modifiche. Altrimenti scopri chi ha modificato il file.

### G03-004 · BASSO — Strumento sparito

**Perché.** Lo strumento «…» non è più presente rispetto all'ultima analisi.

**Come correggere.** Di solito è un aggiornamento normale. Accettalo con: guardia scansiona --accetta-modifiche

### G03-005 · ALTO — Base di confronto danneggiata

**Perché.** Il file della base di confronto (…) è illeggibile oppure è stato modificato fuori da Guardia. Finché il problema resta, i rug pull non possono essere rilevati.

**Come correggere.** Se non sai perché è cambiato, controlla il PC. Per ricrearlo: guardia scansiona --accetta-modifiche

### G03-006 · INFO — Nuovo server

**Perché.** Il server «…» non c'era nell'ultima analisi.

**Come correggere.** Verifica di averlo aggiunto tu. È già stato inserito nella base di confronto.

## G04 — Interferenza tra server (shadowing)

### G04-001 · ALTO — Istruzioni che riguardano altri strumenti (shadowing)

**Perché.** Il testo di «…» dà istruzioni su come usare altri strumenti o server. Così un server malevolo può manipolare server fidati senza toccarli.

**Come correggere.** Rimuovi il server: uno strumento dovrebbe descrivere solo se stesso.

### G04-002 · MEDIO — Cita uno strumento di un altro server

**Perché.** Il testo di «…» nomina «…», uno strumento di un altro server (…). È un possibile segnale di shadowing.

**Come correggere.** Verifica perché lo nomina. Se dà istruzioni su quello strumento, non usare il server.

### G04-003 · BASSO — Stesso nome di uno strumento di un altro server

**Perché.** Lo strumento «…» ha lo stesso nome di uno strumento di …. L'AI potrebbe chiamare quello sbagliato.

**Come correggere.** Disattiva uno dei due server, se non ti servono entrambi.

### G04-004 · MEDIO — Imita uno strumento interno del client

**Perché.** Lo strumento si chiama «…», come uno strumento interno di Claude Code. Può confondere l'AI o chi approva le chiamate.

**Come correggere.** Verifica il server: uno strumento legittimo usa un nome suo.

### G04-005 · ALTO — Cambia i destinatari dei messaggi

**Perché.** Il testo di «…» chiede di cambiare o aggiungere destinatari (email, telefono, copia nascosta). È la tecnica usata per deviare i messaggi verso l'attaccante.

**Come correggere.** Rimuovi il server.

### G04-006 · ALTO — Nome sosia (omoglifo)

**Perché.** Lo strumento «…» usa lettere di un altro alfabeto che sembrano latine (…); lette come lettere normali il suo nome è «…». È un trucco con omoglifi: un nome fatto sembrare affidabile per passare inosservato all'AI o a chi approva le chiamate.

**Come correggere.** Non usare il server: uno strumento legittimo si chiama con lettere normali.

## G05 — Comandi di sistema pericolosi

### G05-001 · ALTO — Avvio tramite shell con comandi concatenati

**Perché.** Il server viene lanciato con … e un comando che concatena più operazioni (per esempio con &&, \| o ;). Così, oltre al server, possono partire altri comandi che non vedi.

**Come correggere.** Fai partire direttamente il programma del server (per esempio "command": "npx") senza passare dalla shell, oppure riduci il comando a una sola operazione chiara.

### G05-002 · CRITICO — Comando PowerShell codificato

**Perché.** Il server avvia … con un comando codificato in base64. Il contenuto è illeggibile a occhio nudo: è una tecnica tipica dei malware per nascondere cosa viene eseguito.

**Come correggere.** Non usare questo server finché non hai decodificato e capito il comando. Se non l'hai scritto tu, rimuovilo.

### G05-003 · ALTO — Programma di Windows spesso abusato

**Perché.** Il server usa …, un programma di Windows legittimo ma usato spesso dagli attaccanti per scaricare o eseguire codice di nascosto.

**Come correggere.** Un server MCP normale non ha bisogno di …. Verifica da dove arriva la configurazione e sostituiscila con il comando ufficiale del server.

### G05-004 · CRITICO — Scarica ed esegue codice da Internet

**Perché.** Il comando di avvio scarica qualcosa da Internet e lo esegue subito, senza controlli. Chi controlla quell'indirizzo può far eseguire qualsiasi cosa sul tuo PC, ogni volta che il server parte.

**Come correggere.** Rimuovi questa configurazione. Installa il server da una fonte ufficiale, con una versione precisa.

### G05-005 · ALTO — Comando distruttivo o che modifica il sistema

**Perché.** Il comando di avvio contiene un'operazione pericolosa («…»): può cancellare dati, cambiare impostazioni di sicurezza o ottenere privilegi elevati.

**Come correggere.** Togli l'operazione dal comando di avvio. Un server MCP non deve modificare il sistema quando parte.

### G05-006 · MEDIO — Programma avviato da una cartella temporanea o da Download

**Perché.** Il programma del server si trova in una cartella temporanea o in Download, dove finiscono spesso file scaricati senza verifica.

**Come correggere.** Installa il server in una cartella stabile, o tramite un gestore di pacchetti, e aggiorna il percorso.

### G05-007 · ALTO — Codice nascosto negli argomenti

**Perché.** Il server avvia … passandogli direttamente del codice da eseguire. Questo codice non sta in nessun file controllabile e può fare qualsiasi cosa.

**Come correggere.** Sposta il codice in un file che puoi leggere e verificare, oppure usa il pacchetto ufficiale del server.

### G05-008 · INFO — Strumento che può eseguire comandi o codice

**Perché.** Lo strumento «…» può eseguire comandi o codice sul tuo PC. Non è un problema in sé, ma è lo strumento più potente a disposizione dell'AI: se l'AI viene ingannata, è da qui che passa il danno.

**Come correggere.** Tieni attiva la conferma manuale per questo strumento e non approvare chiamate che non capisci.

### G05-009 · CRITICO — Esegue codice nascosto, decodificato al momento

**Perché.** Nel codice di «…» c'è un'istruzione che decodifica un testo (per esempio da base64) e lo esegue subito (…). È la firma tipica del malware nei pacchetti: il vero codice resta invisibile a chi lo legge.

**Come correggere.** Non usare il server. Se è un pacchetto pubblico, segnalalo al registro (npm o PyPI) e all'autore.

### G05-010 · BASSO — Comando di shell costruito con testo variabile

**Perché.** Il codice di «…» esegue comandi di shell costruiti unendo testo variabile (…; … punti). Se quel testo arriva dall'AI o da un file, qualcuno potrebbe aggiungere comandi (command injection).

**Come correggere.** È un'indicazione per chi sviluppa il server: passare gli argomenti come elenco, senza shell. Per te: tieni la conferma manuale sulle chiamate a questo server.

### G05-011 · BASSO — Esecuzione dinamica di codice

**Perché.** Il codice di «…» esegue codice costruito durante l'esecuzione (…; … punti). Succede in alcune librerie, ma impedisce di sapere in anticipo cosa verrà eseguito.

**Come correggere.** Nelle librerie note di solito è innocuo. Se il server è poco conosciuto, controlla il punto indicato.

## G06 — Segreti esposti

### G06-001 · ALTO — Chiave segreta scritta in chiaro

**Perché.** La variabile «…» contiene un valore segreto (… caratteri) scritto direttamente nel file. Qualunque programma che legge questo file, compreso un server MCP malevolo, può copiarla.

**Come correggere.** Sostituisci il valore con un riferimento a una variabile d'ambiente (in Claude Code per esempio "${…}") o usa il gestore di credenziali dell'app. Poi rigenera la chiave: va considerata esposta.

### G06-002 · ALTO — Segreto negli argomenti del comando

**Perché.** Un argomento del comando di avvio contiene quello che sembra un segreto (…). Gli argomenti sono visibili a tutti i programmi del PC, per esempio in Gestione attività.

**Come correggere.** Passa il segreto con una variabile d'ambiente, non come argomento. Poi rigenera il segreto.

### G06-003 · ALTO — Segreto in chiaro nelle intestazioni HTTP

**Perché.** L'intestazione «…» contiene un segreto (… caratteri) scritto nel file di configurazione.

**Come correggere.** Usa un riferimento a una variabile (per esempio "Bearer $…") o l'accesso OAuth del client. Poi rigenera il segreto.

### G06-004 · ALTO — Credenziali dentro l'indirizzo

**Perché.** L'indirizzo contiene credenziali o una chiave (…). Gli indirizzi finiscono spesso nei registri dei server e nella cronologia.

**Come correggere.** Togli la chiave dall'indirizzo e passala come intestazione o con OAuth. Poi rigenerala.

### G06-005 · ALTO — Chiede all'AI di inviare segreti

**Perché.** Il testo di «…» chiede di inviare chiavi, token, password o cookie.

**Come correggere.** Rimuovi il server e cambia i segreti che potrebbe aver ricevuto.

### G06-006 · BASSO — Chiede un segreto come parametro

**Perché.** Lo strumento «…» ha un parametro «…»: l'AI dovrà maneggiare un segreto e potrebbe mostrarlo o passarlo altrove.

**Come correggere.** Preferisci server che leggono i segreti da variabili d'ambiente o tramite OAuth.

### G06-007 · ALTO — Segreto scritto nel codice

**Perché.** Il codice di «…» contiene quello che sembra un segreto (…). Chiunque abbia il pacchetto può leggerlo e usarlo.

**Come correggere.** Se il server è tuo, sposta il segreto in una variabile d'ambiente e rigeneralo. Se non è tuo, segnalalo all'autore.

### G06-008 · ALTO — Il codice impacchetta tutte le variabili d'ambiente

**Perché.** Il codice di «…» trasforma in testo tutte le variabili d'ambiente (…). Di solito contengono chiavi e token: è un passaggio tipico prima di inviarle altrove.

**Come correggere.** Controlla dove finisce quel testo. Se viene inviato in rete, non usare il server.

## G07 — Accesso a file sensibili

### G07-001 · ALTO — Accesso a file con chiavi o credenziali

**Perché.** Il server riceve un percorso verso file molto sensibili (…): chiavi SSH, credenziali cloud, dati dei browser o portafogli. Se il server viene compromesso o ingannato, può leggerli e inviarli fuori.

**Come correggere.** Togli quel percorso dalla configurazione. Dai al server solo la cartella di lavoro che gli serve davvero.

### G07-002 · ALTO — Accesso alle configurazioni degli agenti AI

**Perché.** Il server riceve il percorso di una configurazione MCP (…). Questi file contengono chiavi e comandi di altri server: sono il bersaglio preferito degli attacchi di tool poisoning.

**Come correggere.** Un server MCP non dovrebbe leggere le configurazioni degli altri. Rimuovi il percorso.

### G07-003 · MEDIO — Accesso a file .env

**Perché.** Il server riceve un percorso verso un file .env (…), che di solito contiene password e chiavi.

**Come correggere.** Verifica che serva davvero. Altrimenti rimuovi il percorso o sposta i segreti in un gestore di credenziali.

### G07-004 · CRITICO — Chiede di leggere o inviare file sensibili

**Perché.** Il testo di «…» chiede all'AI di leggere o inviare file molto sensibili (chiavi SSH, .env, configurazioni MCP, portafogli). È il cuore degli attacchi di tool poisoning.

**Come correggere.** Rimuovi subito il server e verifica di non averlo già usato. Se lo hai usato, cambia le chiavi coinvolte.

### G07-005 · ALTO — Il codice usa percorsi di file con credenziali

**Perché.** Il codice di «…» contiene il percorso di file molto sensibili (…). Se lo stesso file usa anche la rete il livello è CRITICO, perché potrebbe leggerli e inviarli.

**Come correggere.** Verifica perché il server ne ha bisogno. Un server MCP normale non legge chiavi SSH, credenziali cloud o dati dei browser.

### G07-006 · MEDIO — Il codice legge o modifica configurazioni di agenti AI

**Perché.** Il codice di «…» usa file di configurazione di agenti AI (…) in … punti (…). Spesso sono script che aggiungono il server alla configurazione, ma lo stesso accesso permette di leggere le chiavi degli altri server.

**Come correggere.** Verifica che si tratti di uno script di installazione o rimozione. Se il server tocca queste configurazioni mentre lavora, non usarlo.

## G08 — Permessi eccessivi

### G08-001 · ALTO — Accesso all'intero disco

**Perché.** Il server riceve come percorso la radice del disco o la cartella di tutti gli utenti (…). Può leggere o modificare qualsiasi file accessibile.

**Come correggere.** Limita il server alle sole cartelle del progetto su cui deve lavorare.

### G08-002 · MEDIO — Accesso all'intera cartella personale

**Perché.** Il server riceve tutta la tua cartella personale (…), che include documenti, chiavi SSH e configurazioni delle app.

**Come correggere.** Indica solo le sottocartelle necessarie, per esempio la cartella di un singolo progetto.

### G08-003 · ALTO — Opzione che disattiva le protezioni

**Perché.** Il server è avviato con l'opzione «…», che disattiva conferme o protezioni.

**Come correggere.** Rimuovi l'opzione, a meno che tu non sappia esattamente perché serve e in quale ambiente isolato gira.

### G08-004 · ALTO — Container con privilegi elevati o accesso al PC

**Perché.** Il container del server è avviato con un'opzione (…) che gli dà accesso al sistema che lo ospita. In pratica annulla l'isolamento del container.

**Come correggere.** Togli l'opzione e monta solo le cartelle necessarie, possibilmente in sola lettura (:ro).

### G08-005 · MEDIO — Container sulla rete del PC

**Perché.** Il container usa direttamente la rete del PC, quindi può raggiungere servizi locali che dovrebbero restare privati.

**Come correggere.** Usa la rete predefinita del container e pubblica solo le porte necessarie.

### G08-006 · MEDIO — Annotazioni ingannevoli

**Perché.** Lo strumento «…» si dichiara innocuo (…), ma dal nome sembra modificare o cancellare qualcosa. Alcuni client si fidano di queste annotazioni per non chiedere conferma.

**Come correggere.** Non fidarti dell'annotazione: tieni la conferma manuale per questo strumento.

## G09 — Rete sospetta

### G09-001 · ALTO — Server remoto senza cifratura

**Perché.** Il collegamento con «…» usa http o ws, senza cifratura. Chiunque sulla stessa rete può leggere o modificare i messaggi, compresi token e risultati.

**Come correggere.** Usa l'indirizzo https:// (o wss://). Se il server non lo supporta, non usarlo su reti di cui non ti fidi.

### G09-002 · ALTO — Indirizzo dei metadati cloud

**Perché.** L'indirizzo punta a …, usato dai servizi cloud per distribuire credenziali interne. È un bersaglio classico degli attacchi SSRF.

**Come correggere.** Rimuovi l'indirizzo. Un server MCP non ha motivo di contattare i metadati cloud.

### G09-003 · MEDIO — Indirizzo di rete interna

**Perché.** L'indirizzo punta a …, una rete privata. Va bene se è un tuo servizio, ma un server malevolo può usarlo per esplorare la rete di casa o dell'ufficio.

**Come correggere.** Verifica che l'indirizzo sia davvero un tuo servizio. Altrimenti rimuovilo.

### G09-004 · BASSO — Indirizzo IP diretto

**Perché.** L'indirizzo usa un IP numerico (…) invece di un nome di dominio: è più difficile capire a chi appartiene.

**Come correggere.** Preferisci l'indirizzo ufficiale con nome di dominio e https.

### G09-005 · BASSO — Server locale via HTTP

**Perché.** Il server gira sul tuo PC (…) via HTTP. Qualunque programma, o pagina web aperta sul PC, può provare a contattarlo.

**Come correggere.** Verifica che il server richieda un token e accetti solo connessioni locali. Se possibile usa il trasporto stdio.

### G09-006 · ALTO — Verifica dei certificati disattivata

**Perché.** L'impostazione «…» disattiva il controllo dei certificati HTTPS: un attaccante sulla rete può fingersi il server.

**Come correggere.** Rimuovi l'impostazione. Se usi un certificato aziendale, installalo nel sistema invece di disattivare i controlli.

### G09-007 · MEDIO — Servizio di tunnel o di raccolta dati

**Perché.** L'indirizzo usa …, un servizio spesso usato per tunnel temporanei o per raccogliere dati inviati da altri. È tipico delle esfiltrazioni.

**Come correggere.** Usa solo indirizzi ufficiali e stabili. Se non sai perché c'è questo indirizzo, rimuovi il server.

### G09-008 · MEDIO — Indirizzo scritto in forma ingannevole

**Perché.** Il nome … usa caratteri internazionali (punycode) o una forma numerica insolita: può imitare un sito noto o nascondere un indirizzo interno.

**Come correggere.** Controlla l'indirizzo reale e sostituiscilo con quello ufficiale.

### G09-009 · BASSO — Trasporto SSE deprecato

**Perché.** Il server usa il vecchio trasporto HTTP+SSE, deprecato dalla specifica MCP.

**Come correggere.** Passa al trasporto Streamable HTTP, se il server lo supporta.

### G09-010 · ALTO — Chiede di inviare dati a un indirizzo web

**Perché.** Il testo di «…» chiede all'AI di inviare dati a un indirizzo web o a un webhook.

**Come correggere.** Rimuovi il server, a meno che l'invio non sia lo scopo dichiarato e chiaro dello strumento.

### G09-011 · ALTO — Il codice contatta un servizio di tunnel o raccolta dati

**Perché.** Il codice di «…» contiene l'indirizzo di un servizio usato spesso per tunnel temporanei o per raccogliere dati (…).

**Come correggere.** Un server affidabile usa indirizzi propri e stabili. Se non sai perché c'è, non usare il server.

### G09-012 · BASSO — Il codice contatta un indirizzo IP diretto

**Perché.** Il codice di «…» contiene un indirizzo IP pubblico scritto direttamente (…): è più difficile capire a chi appartiene.

**Come correggere.** Verifica a chi appartiene l'indirizzo.

## G10 — Dipendenze e catena di fornitura

### G10-001 · MEDIO — Pacchetto senza versione bloccata

**Perché.** Il pacchetto «…» viene scaricato ed eseguito senza una versione precisa (indicata: …). Se un giorno il pacchetto viene manomesso, la versione nuova parte da sola al prossimo avvio.

**Come correggere.** Indica una versione esatta che hai verificato (per esempio …@1.2.3) e aggiornala tu quando decidi.

### G10-002 · MEDIO — Codice preso direttamente da un repository o da un indirizzo

**Perché.** Il server viene installato da «…», cioè da un repository o da un indirizzo diretto e non da una versione pubblicata. Il contenuto può cambiare in qualsiasi momento.

**Come correggere.** Usa un pacchetto pubblicato con versione esatta, oppure indica un commit preciso.

### G10-003 · MEDIO — Nome molto simile a un pacchetto noto

**Perché.** Il pacchetto «…» ha un nome quasi identico a «…». È la tecnica del typosquatting: pubblicare un pacchetto con un nome sbagliato di una lettera.

**Come correggere.** Controlla il nome esatto sulla pagina ufficiale del server. Se era un errore di battitura, correggilo subito.

### G10-004 · MEDIO — Registro di pacchetti non ufficiale

**Perché.** Il pacchetto viene scaricato da un registro diverso da quello ufficiale (…).

**Come correggere.** Verifica di fidarti di quel registro. Altrimenti usa quello ufficiale.

### G10-005 · MEDIO — Immagine container senza versione fissata

**Perché.** L'immagine «…» non ha una versione fissa (manca il tag oppure è latest): può cambiare a ogni avvio.

**Come correggere.** Indica un tag preciso o, meglio ancora, l'impronta digest (@sha256:...).

### G10-006 · MEDIO — Script eseguiti automaticamente all'installazione

**Perché.** Nel server «…» e nelle sue dipendenze ci sono … script che partono da soli durante l'installazione, per esempio: …. Girano prima che tu usi il server, con i tuoi permessi. Il livello sale ad ALTO se uno script scarica o esegue codice da Internet.

**Come correggere.** Controlla gli script indicati. Per installare senza eseguirli: npm install --ignore-scripts (alcuni pacchetti potrebbero non funzionare).

### G10-007 · MEDIO — Dipendenza presa da un repository o da un indirizzo

**Perché.** Il server «…» dipende da codice preso direttamente da un repository o da un indirizzo (…) invece che da una versione pubblicata. Il contenuto può cambiare senza preavviso.

**Come correggere.** Chiedi all'autore di usare versioni pubblicate, oppure di fissare un commit preciso.

### G10-008 · MEDIO — Dipendenza con nome quasi identico a un pacchetto famoso

**Perché.** Il server «…» usa il pacchetto «…», a una lettera di distanza da «…». È la tecnica del typosquatting.

**Come correggere.** Verifica che sia davvero il pacchetto voluto. Se è un errore di battitura, potrebbe essere stato installato codice malevolo.

### G10-009 · BASSO — Dipendenza senza versione

**Perché.** Il server «…» dichiara dipendenze senza alcuna versione (…; … in totale): a ogni installazione può arrivare codice diverso.

**Come correggere.** Indica versioni precise o usa un file di blocco (package-lock.json, uv.lock).

### G10-010 · ALTO — setup.py esegue codice durante l'installazione

**Perché.** Il file setup.py di «…» usa: …. Questo codice parte durante l'installazione del pacchetto, prima che tu possa controllarlo.

**Come correggere.** Controlla setup.py. Un pacchetto moderno non dovrebbe avviare programmi o usare la rete durante l'installazione.

### G10-011 · BASSO — Nessun file di blocco delle versioni

**Perché.** Il progetto in … non ha un file di blocco (per esempio package-lock.json o uv.lock): le versioni delle dipendenze possono cambiare a ogni installazione.

**Come correggere.** Genera e conserva un file di blocco: npm install crea package-lock.json, uv lock crea uv.lock.

## G11 — Esposizione in rete

### G11-001 · MEDIO — Server in ascolto su tutta la rete

**Perché.** Il server accetta connessioni da tutta la rete (0.0.0.0), non solo dal tuo PC.

**Come correggere.** Usa 127.0.0.1 per limitare l'accesso al tuo computer.

## G12 — Igiene della configurazione

### G12-001 · BASSO — Configurazione incompleta

**Perché.** Al server «…» manca il comando o l'indirizzo. Così non può funzionare: può essere un residuo o un segnaposto.

**Come correggere.** Completa la configurazione oppure rimuovi la voce.

### G12-002 · BASSO — Tipo di trasporto sconosciuto

**Perché.** Il tipo di trasporto «…» non è uno di quelli previsti da MCP.

**Come correggere.** Usa stdio, http oppure sse.

### G12-003 · INFO — Stesso nome, definizioni diverse

**Perché.** Il nome «…» è configurato in più posti con … definizioni diverse. Può creare confusione su quale versione stai usando davvero.

**Come correggere.** Allinea le configurazioni o dai nomi diversi ai server diversi.

### G12-004 · MEDIO — Chiave duplicata nel file

**Perché.** Il file contiene due volte la chiave «…». Programmi diversi possono leggere valori diversi: è un modo per nascondere un valore a chi controlla il file.

**Come correggere.** Tieni una sola definizione e rimuovi il duplicato.

### G12-005 · ALTO — Plugin che punta fuori dalla sua cartella

**Perché.** Il plugin cerca di caricare un file esterno alla sua cartella («…»). Guardia lo ha ignorato.

**Come correggere.** Verifica il plugin: un plugin legittimo usa solo file al suo interno.

### G12-006 · MEDIO — File di configurazione non analizzabile

**Perché.** Il file non è stato letto (…), quindi i server che contiene non sono stati controllati.

**Come correggere.** Correggi il formato o i permessi del file e ripeti l'analisi.

### G12-007 · BASSO — Parte del codice del server non analizzata

**Perché.** … file del server «…» non sono stati analizzati: troppo grandi, illeggibili o scritti in modo da non poter essere letti. Un file costruito apposta può servire a nascondere strumenti.

**Come correggere.** Controlla i file indicati nel rapporto JSON. Se il server viene da una fonte ufficiale, di solito è innocuo.

### G12-008 · MEDIO — Avviato da un altro programma «guardia»

**Perché.** La voce "…" passa da un programma che si chiama come Guardia ma non è questa installazione (…). Se è una tua vecchia copia di Guardia va solo ricollegata; se non la riconosci potrebbe essere un programma travestito, che Guardia non può controllare.

**Come correggere.** Se è una tua copia di Guardia, apri l'app e premi «Ricollega» nella sezione Scudo (oppure: guardia scudo ricollega --nome NOME --conferma). Se non la riconosci, togli la voce e controlla quel programma.

### G12-009 · MEDIO — Il programma dello Scudo non esiste più

**Perché.** La voce "…" passa dallo Scudo, ma il programma … non c'è più (per esempio la cartella di Guardia è stata spostata o cancellata): l'app AI non riesce ad avviare questo server.

**Come correggere.** Apri Guardia e premi «Ricollega» nella sezione Scudo (oppure: guardia scudo ricollega --tutti --conferma), poi riavvia l'app AI.

## G13 — Registro a prova di manomissione

### G13-001 · ALTO — Registro manomesso

**Perché.** Il registro a prova di manomissione (…) non supera la verifica: …. Qualcuno o qualcosa ha modificato, cancellato o aggiunto righe fuori da Guardia.

**Come correggere.** Non cancellarlo: è la prova dell'accaduto. Controlla il PC, poi esegui: guardia registro verifica

### G13-002 · MEDIO — Registro non verificabile

**Perché.** Il registro (…) non può essere verificato del tutto: ….

**Come correggere.** Se hai cambiato utente di Windows o ripristinato il PC è normale. Altrimenti controlla chi ha modificato la cartella di Guardia.

## G14 — Skill

### G14-001 · INFO — La skill contiene script eseguibili

**Perché.** La skill «…» contiene … script (…) che l'AI può eseguire sul tuo PC quando usa la skill.

**Come correggere.** Leggi gli script prima di usare la skill, soprattutto se viene da una fonte che non conosci.

### G14-002 · MEDIO — La skill si concede strumenti potenti senza conferma

**Perché.** L'intestazione della skill «…» autorizza … senza chiedere conferma ogni volta (campo allowed-tools). Se le istruzioni della skill vengono manipolate, i comandi partono senza che tu li approvi.

**Come correggere.** Rimuovi o restringi allowed-tools (per esempio Bash(git status:\*)) se non ti fidi completamente della skill.

### G14-003 · ALTO — La skill scarica ed esegue codice da Internet

**Perché.** La skill «…» contiene un comando che scarica uno script da Internet e lo esegue subito (…). Chi controlla quell'indirizzo può eseguire qualsiasi cosa sul tuo PC. Nelle istruzioni della skill è MEDIO, perché l'AI ti chiede conferma; in uno script allegato è ALTO.

**Come correggere.** Installa il programma dal sito ufficiale verificandone la provenienza, invece di eseguire uno script scaricato al volo.

---

Guardia MCP — by Alexander Puglisi. Licenza Apache 2.0.
