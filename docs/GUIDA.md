# Guardia MCP passo passo

**by Alexander Puglisi** · [English version](GUIDE.md)

Questa guida ti accompagna dal download al primo server protetto, con le schermate vere dell'app.
Le foto vengono da un PC finto creato apposta (`scripts/make_tutorial.py`): nomi, percorsi e
segreti sono inventati.

Non serve saper programmare. Ti servono Windows 10 o 11 e cinque minuti.

---

## 1. Scarica e controlla

1. Apri la pagina [**Releases**](https://github.com/AlexanderPuglisi/guardia-mcp/releases/latest) e
   scarica `GuardiaMCP-0.2.1-windows-x64.zip`.
2. Controlla che il file sia quello giusto. Apri **PowerShell** e scrivi:

   ```powershell
   Get-FileHash "$env:USERPROFILE\Downloads\GuardiaMCP-0.2.1-windows-x64.zip"
   ```

   Il valore che compare deve essere uguale a quello scritto in `SHA256SUMS.txt`, nella stessa
   pagina. Se è diverso, non aprire lo zip.

## 2. Estrai e apri

1. Tasto destro sullo zip → **Estrai tutto** → scegli una cartella che non sposterai, per esempio
   `C:\Users\TUO-NOME`. Si crea la cartella `GuardiaMCP`.
2. Dentro trovi due programmi:
   - **`GuardiaMCP.exe`**: l'app con la finestra, quella che usi tu;
   - **`guardia.exe`**: la riga di comando; la usano anche lo Scudo e le app AI, non cancellarla.
3. Doppio clic su **`GuardiaMCP.exe`**. La prima volta Windows può mostrare un avviso blu
   («Windows ha protetto il PC»), perché il programma non è ancora firmato digitalmente: scegli
   **Ulteriori informazioni** → **Esegui comunque**.

> Usi **Claude Desktop installato dal Microsoft Store**? Apri Guardia da qui almeno una volta
> **prima** di proteggere i server: così la cartella dei dati nasce nel posto giusto.

## 3. Panoramica: com'è messo il tuo PC

All'apertura Guardia fa da sola la prima scansione. La **Panoramica** conta i problemi per gravità
e mostra quelli da guardare per primi. La scansione legge soltanto: non cambia niente sul PC.

![Panoramica](tutorial/it-01-overview.png)

## 4. Problemi: cosa c'è e come si sistema

La sezione **Problemi** elenca tutto dal più grave. Usa i filtri in alto (Gravi, Medi, Minori) o
la ricerca.

![Problemi](tutorial/it-02-findings.png)

Clicca un problema per vedere il dettaglio:

- **Dove**: il file esatto. La piccola icona accanto al percorso lo copia, pronto da incollare in
  Esplora risorse; sotto c'è la riga.
- **Trovato**: cosa ha visto Guardia (i segreti non compaiono mai interi).
- **Perché**: il rischio, spiegato in parole semplici.
- **Come correggere**: cosa fare, passo per passo.

![Dettaglio di un problema](tutorial/it-03-finding-detail.png)

Dopo aver corretto, premi **Scansiona ora**: il problema sparisce.

## 5. Scudo: proteggi un server mentre l'AI lavora

Lo **Scudo** si mette tra l'app AI e un server MCP e controlla ogni messaggio.

1. **Chiudi l'app AI** (Claude, Cursor, VS Code…).
2. In **Scudo**, premi **Proteggi** accanto al server e conferma. Guardia salva una copia di
   sicurezza del file e cambia solo quella voce.
3. Riapri l'app AI e usala come sempre.

![Scudo](tutorial/it-04-shield.png)

Da questo momento:

- gli strumenti **nuovi o cambiati** di quel server restano nascosti finché non li approvi, sempre
  in questa sezione;
- strumenti avvelenati, segreti e richieste di password vengono fermati anche senza regole tue;
- ogni decisione finisce nel **Registro**.

Per tornare indietro: **Togli protezione** accanto al server.

## 6. Le tue regole (facoltativo)

Le regole ti permettono di decidere tu cosa bloccare, nascondere o farti chiedere.

1. In **Scudo** → **Regole dello Scudo** premi **Crea le regole d'esempio**.
2. Premi **Modifica le regole**: l'esempio contiene 5 regole utili, spiegate riga per riga.
3. Cambia quello che vuoi e premi **Salva e approva**. Se c'è un errore, Guardia ti mostra la riga e
   non salva niente.

![Editor delle regole](tutorial/it-05-rules-editor.png)

Fallo con l'app AI chiusa: finché le regole non sono approvate, i server protetti restano bloccati.

## 7. La finestra di conferma

Quando una regola dice `chiedi`, compare questa piccola finestra sempre in primo piano. Leggi chi
chiede cosa e perché, poi scegli **Consenti** o **Blocca**. Se non rispondi entro 60 secondi,
Guardia **blocca**. L'AI non può rispondere al posto tuo.

![Finestra di conferma](tutorial/it-08-confirm.png)

## 8. Impostazioni e cronologia

In **Impostazioni** scegli lingua e cosa analizzare, e aggiungi le cartelle dei tuoi progetti. Ogni
modifica viene annotata nella **Cronologia delle modifiche** con il valore di prima: **Ripristina**
lo rimette com'era.

![Impostazioni](tutorial/it-06-settings.png)

## 9. Registro: la storia che non si può riscrivere

Il **Registro** contiene ogni scansione e ogni decisione dello Scudo, in una catena firmata: se
qualcuno cancella o cambia una riga, Guardia se ne accorge.

![Registro](tutorial/it-07-ledger.png)

---

## Se qualcosa non va

| Cosa vedi | Cosa vuol dire | Cosa fare |
|---|---|---|
| «Windows ha protetto il PC» | Il programma non è firmato digitalmente | **Ulteriori informazioni** → **Esegui comunque** |
| `Failed to resolve Python.Runtime.Loader.Initialize` | Solo con la versione **0.2.0**: Windows bloccava le librerie dello zip scaricato | Scarica la **0.2.1**. In alternativa: tasto destro sullo zip → **Proprietà** → **Sblocca**, poi estrai di nuovo |
| Problema **G12-006** «File di configurazione non analizzabile» | Guardia non è riuscita a leggere quel file, quindi i server che contiene non sono stati controllati. Il dettaglio dice la riga dell'errore | Apri il file indicato e correggi il formato. Nella 0.2.1 un file **vuoto** non è più segnalato |
| Un server non parte dopo **Proteggi** | La cartella di Guardia è stata spostata o cancellata | Rimetti la cartella dov'era, oppure **Togli protezione** e proteggi di nuovo |

Per disinstallare, segui la sezione **Disinstallare** del [README](../README.md).
Domande o problemi: apri una *issue* su GitHub; per una vulnerabilità usa **Security → Report a
vulnerability**.
