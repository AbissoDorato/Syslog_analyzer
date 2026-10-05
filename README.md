# Syslog Analyser

Analisi locale dei syslog per preparare ticket su comportamenti osservati durante un possibile picco di traffico del PC. Il programma identifica aumenti di eventi, ne ricostruisce il contesto e propone cause da un catalogo di regole modificabile.

**Gli eventi syslog non misurano la banda.** Il ticket distingue evidenze, ipotesi e controlli necessari per confermare il traffico con contatori di interfaccia, firewall, proxy o NetFlow. Le percentuali dei messaggi non sono probabilità di attacco.

## Avvio

Servono Python **3.10 o successivo** e un browser moderno. Non ci sono pacchetti Python da installare.

### Windows

Doppio clic su `Avvia Syslog Analyser.bat`, oppure:

```powershell
py -3 app.py
```

Se usi un'installazione senza launcher `py`, esegui `python app.py`.

### Linux

```sh
sh avvia.sh
```

In alternativa: `python3 app.py`, oppure `chmod +x avvia.sh` e `./avvia.sh`.

La pagina è disponibile su `http://127.0.0.1:8765`. L'opzione `--port 9000` cambia porta; `--no-browser` evita l'apertura automatica. Entrambi gli script inoltrano queste opzioni. `Ctrl+C` termina il servizio. L'apertura del browser può non essere disponibile in sessioni Linux senza desktop.

## Flusso di lavoro

1. Carica CSV, TXT o LOG (massimo 30 MB). Sono letti UTF-8 e UTF-16 con BOM; il contenuto decodificato deve rientrare in 30 MB UTF-8.
2. Controlla colonne riconosciute e avvisi di qualità. Imposta il fuso per date che ne sono prive e l'ordine giorno/mese delle date con slash.
3. Seleziona host e finestra nel **Dossier per il ticket**. Leggi conteggi, categorie, processi, suggerimenti ed evidenze.
4. Scegli una causa dal catalogo oppure lascia **Causa da determinare**. Una causa scelta manualmente viene indicata come tale se le soglie della regola non sono soddisfatte.
5. Modifica il Markdown e copia il ticket, scarica `.md` o esporta il dossier `.json`. La scelta della causa e le modifiche vengono conservate in memoria quando cambi finestra. Un nuovo caricamento o ricalcolo le azzera.

Non vengono creati ticket su servizi esterni. I dati restano in memoria; diventano file solo quando scegli di scaricarli. I report contengono estratti dei log: rivedili prima di condividerli.

### Esempio incluso

Carica [`examples/demo.csv`](examples/demo.csv), che contiene dati sintetici. Con finestra 5 minuti, moltiplicatore 2 e minimo 5:

- `pc-a`: 30 eventi nella finestra delle 10:15 UTC, di cui 24 retry (**80%**), contro 1 evento/finestra nello storico. Suggerimento: ciclo di retry o servizio remoto non raggiungibile.
- `pc-b`: 15 fallimenti di autenticazione e un accesso riuscito dallo stesso IP e utente. Sono suggeriti sia problemi di credenziali sia un approfondimento compatibile con T1110. Nessun attacco viene dichiarato confermato.

## Colonne CSV

| Colonna | Uso |
|---|---|
| `TimeGenerated` | Timestamp di riferimento per finestre, sequenze e albero |
| `Computer` | Identità dell'host per separare i contesti |
| `Facility` | Sottosistema syslog, distribuzioni e contesto del ticket |
| `SecurityLevel` | Livello syslog normalizzato: numeri 0–7 e alias come `err`, `warn`, `informational` |
| `SyslogMessage` | Testo per classificazione, evidenze e campi di rete espliciti |
| `Processname` | Processo che **registra** l'evento; può differire dal servizio avviato |
| `HostIP` | Indirizzo dell'host del record, non una destinazione remota |

Intestazioni senza distinzione maiuscole/minuscole, spazi, trattini o underscore. Sono conservati gli alias comuni delle versioni precedenti, compresi `message`, `timestamp`, `process_name`, `host` e `severity`. Il delimitatore viene scelto tra virgola, punto e virgola, tab e pipe in base alle intestazioni riconosciute. Sono supportati campi quotati, messaggi multilinea e BOM.

I campi espliciti del CSV hanno precedenza sul messaggio. Un `TimeGenerated` presente ma non valido viene segnalato, senza sostituirlo silenziosamente con un'altra data. Gli eventi non databili restano nei conteggi generali, ma sono esclusi da spike e sequenze.

Per TXT/LOG sono riconosciuti syslog RFC 3164, RFC 5424 e prefissi ISO con host e tag del processo. PID e facility vengono estratti quando disponibili. Le date vengono normalizzate in **UTC**: i timestamp senza fuso usano l'offset scelto (predefinito `+00:00`); quelli RFC 3164 senza anno usano l'anno corrente UTC con avviso. Per log che attraversano cambi d'ora legale, preferisci un export con offset esplicito.

## Rilevamento dei picchi

La rilevazione avviene separatamente per **host** e per **host + nome del processo**. Un aumento di un processo può quindi essere individuato anche se il totale dell'host rimane stabile.

Per ogni finestra si confrontano al massimo le 12 precedenti dell'host, includendo gli intervalli senza log a partire dalla sua prima osservazione. La finestra in esame e quelle future non entrano nella baseline. Servono almeno 3 finestre precedenti.

La soglia è il massimo tra:

- minimo di eventi configurato (predefinito 5);
- media precedente × moltiplicatore (predefinito 2), arrotondata per eccesso;
- mediana precedente + `3 × 1,4826 × MAD`, superata strettamente; MAD è la mediana degli scarti assoluti dalla mediana.

La finestra deve anche superare la media precedente. Le finestre iniziali o senza aumento possono essere mostrate come **finestre da esaminare**, con indicazione che lo spike non è dimostrato. Se un host non ha spike, viene proposta la sua finestra più popolata.

Questi criteri sono euristiche, non un test di significatività statistica. Gli zeri presuppongono raccolta continua: buchi nell'export, finestre ai bordi del periodo, duplicati e cambi del livello di logging possono alterare il confronto. I record identici sono segnalati ma conservati, perché potrebbero rappresentare eventi distinti con lo stesso timestamp.

## Categorie e possibili cause

Ogni evento riceve **una categoria primaria**, in ordine di regola. Le quote nella scheda sono riferite a **tutti gli eventi dello stesso host nella finestra selezionata**. I tipi comprendono:

- autenticazioni fallite e riuscite;
- errori DNS, retry di rete e blocchi firewall;
- errori/riavvii e avvii dichiarati di servizi;
- backup/sincronizzazioni, aggiornamenti/download e job pianificati;
- connessioni e segnalazioni esplicite di scansione o tunnel DNS;
- eventi non classificati.

Ogni ipotesi espone conteggio, quota, soglie minime, eventuali requisiti aggiuntivi, record di supporto, controlli suggeriti e variazione in **punti percentuali** rispetto alla composizione precedente. Più cause possono spiegare gli stessi eventi: le quote delle ipotesi non vanno sommate.

Le regex, soglie, etichette, verifiche e riferimenti sono in [`catalog.json`](catalog.json). Per modificarli, cambia il file e riavvia il server. Le condizioni aggiuntive (`gate`) sono implementate in [`insights.py`](insights.py). Il catalogo viene caricato dal disco, senza download, API di IA o modelli remoti.

### MITRE ATT&CK

Il catalogo contiene un sottoinsieme curato, consultato il **5 ottobre 2026**:

| Riferimento | Evidenze richieste dalla regola locale |
|---|---|
| [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Almeno 10 fallimenti, almeno il 40% della finestra e almeno 5 associati alla stessa sorgente esplicita |
| [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Soglie di volume/quota più segnalazioni esplicite di scansione oppure almeno 10 eventi in uscita verso almeno 10 destinazioni o porte |
| [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) | Segnalazioni esplicite di tunnel/beacon DNS sopra soglia; semplici errori DNS non attivano questa ipotesi |

Queste sono **associazioni candidate da validare**, non rilevazioni MITRE certificate. Una percentuale elevata, una facility o un livello `error` da soli non provano una tecnica. Le alternative operative e i controlli da effettuare rimangono nel ticket. Il sito MITRE viene aperto solo se l'utente clicca un collegamento.

## Correlazioni e albero temporale

- Associazioni processo–facility, processo–livello e processo–HostIP calcolate per host.
- Co-occorrenze tra i 20 processi più attivi di ciascun host: almeno 2 finestre condivise, indice Jaccard = intersezione/unione delle finestre attive. Non è un indice di causalità.
- Sequenze di almeno 3 fallimenti seguiti da un accesso riuscito **nella stessa finestra, sullo stesso host, con IP sorgente e utente espliciti coincidenti**. Gli IP o gli utenti mancanti non vengono inventati.
- Estrazione di `SRC/DST`, `src_ip/dst_ip`, `saddr/daddr`, porte esplicite e sorgenti SSH. L'uscita è attribuita solo quando `SRC` coincide con `HostIP` e `DST` è diverso; l'ingresso richiede la condizione inversa. Negli altri casi la direzione resta non determinabile.
- L'albero distingue **avvio segnalato**, **avvio richiesto** e **prima osservazione; avvio non dimostrato**. Un messaggio di systemd non prova che systemd sia il processo avviato; viene mostrato il servizio nominato. Non si ricostruisce un albero parent/child del sistema operativo senza dati PPID.
- Eventi successivi dello stesso nome di processo, con PID compatibile se presente, entro 30 minuti e fino al successivo avvio riconosciuto. Le vicinanze di altri processi sono mostrate entro ± la finestra scelta, sullo stesso host.

## Evidenze e limiti

Il ticket include host/IP, finestra UTC, baseline, categorie, processi, ipotesi, controlli, record originali campionati, qualità del parsing e versione del catalogo. Il SHA-256 identifica **il testo UTF-8 analizzato**, non necessariamente i byte originali di un export UTF-16. Il dossier JSON aggiunge i parametri e la causa selezionata.

- Analisi dei primi **250.000 eventi**; eventuale troncamento segnalato.
- Massimo **50 dossier** ordinati per presenza di anomalia ed eccesso di eventi. Il conteggio totale delle finestre rimane visibile.
- Massimo **30 evidenze** per dossier, con campioni delle regole attivate; testo fino a 2.000 caratteri per campo con indicazione del troncamento.
- Grafico generale con al massimo 600 barre aggregate, mantenendo il totale degli eventi.
- Albero limitato alle 100 osservazioni/avvii più recenti, 20 eventi successivi e 10 vicinanze per nodo. La ricerca di vicinanze ispeziona al massimo 2.000 record per nodo e segnala il limite.
- Colonne di rete non standard, processi registrati da un collettore anziché dall'origine, messaggi proprietari e timestamp incompleti possono richiedere regole dedicate.

## Struttura e verifiche

| File | Responsabilità |
|---|---|
| `app.py` | Server HTTP su loopback, validazione richieste e file statici |
| `parsing.py` | Colonne, formati syslog, date e qualità dell'input |
| `analysis.py` | Finestre per host/processo, baseline, correlazioni e dossier |
| `insights.py` | Regole locali, endpoint espliciti, evidenze e testo ticket |
| `catalog.json` | Cause predefinite, categorie, soglie, verifiche e MITRE |
| `index.html`, `app.js`, `styles.css` | Dashboard, scelta causa, bozze ed esportazione locale |

Test backend, casi di analisi e API (solo libreria standard):

```sh
python3 -m unittest discover -s tests -v
```

Su Windows usa `py -3 -m unittest discover -s tests -v`. Per i controlli della logica frontend, opzionali per lo sviluppo, serve Node.js:

```sh
node tests/test_frontend.cjs
```

La variabile `PYTHON` può indicare un interprete specifico per questo controllo. Il test frontend verifica il contratto con l'HTML, escaping, scelta manuale, conservazione delle bozze e download simulati; non sostituisce una prova visiva in browser.
