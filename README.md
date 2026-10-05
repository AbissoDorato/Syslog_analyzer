# Syslog Analyser

Analizzatore locale di log Linux e syslog con una dashboard per individuare i processi più attivi, i messaggi ricorrenti e gli spike temporali. L'applicazione funziona su Windows e Linux e usa solo la libreria standard di Python.

## Requisiti

- Python 3.10 o successivo
- Un browser moderno

Non servono pacchetti Python, account, connessione Internet o servizi esterni.

## Avvio su Windows

Fai doppio clic su `Avvia Syslog Analyser.bat`. In alternativa, apri PowerShell nella cartella del progetto ed esegui:

```powershell
py -3 app.py
```

Se il comando `py` non è disponibile, usa `python app.py`.

## Avvio su Linux

Apri un terminale nella cartella del progetto ed esegui:

```sh
chmod +x avvia.sh
./avvia.sh
```

In alternativa, avvia direttamente l'app con `python3 app.py`.

Per scegliere una porta diversa, aggiungi `--port NUMERO` al comando. Per esempio: `python3 app.py --port 9000`. L'opzione `--no-browser` avvia il server senza aprire automaticamente il browser. Per fermare il servizio, premi `Ctrl+C` nel terminale.

L'app apre `http://127.0.0.1:8765` nel browser e ascolta solo sull'interfaccia locale del computer.

## Importazione e risultati

Trascina nella pagina un file `.txt`, `.log` o `.csv` (massimo 30 MB). Per i file di testo, ogni riga non vuota è trattata come un evento. Sono riconosciuti i formati syslog RFC 3164 e RFC 5424, le righe ISO con `host processo[pid]: messaggio` e le righe journal con data, host e processo. Le righe non riconosciute restano conteggiate e visibili con il processo `unknown`.

Per i CSV, l'applicazione cerca una colonna per il messaggio (`message`, `msg`, `event`, `log`, `content`, `description` o `testo`) e colonne comuni per timestamp, host, processo, PID e severità. Se le intestazioni sono diverse, i campi possono comunque comparire nel messaggio aggregato.

La dashboard mostra i conteggi per processo, la severità, gli host più attivi e i messaggi ricorrenti. Numeri e identificativi nel testo vengono normalizzati durante l'aggregazione, così eventi simili vengono raggruppati. Selezionando un processo puoi vedere i suoi messaggi più frequenti.

Gli spike sono calcolati per finestre temporali configurabili. Una finestra viene segnalata se contiene almeno 3 eventi e supera la media delle finestre di quel processo per il moltiplicatore impostato. Il confronto include gli intervalli senza eventi quando l'intervallo complessivo è entro 20.000 finestre. I log senza timestamp restano analizzabili per conteggi e processi, ma non contribuiscono al grafico temporale o ai picchi.

## Limiti

Il parser usa euristiche leggere e non copre tutti i formati personalizzati di syslog, auditd o applicazioni. Se i processi non vengono attribuiti correttamente, verifica i nomi delle colonne CSV. Le date RFC 3164 non includono l'anno: per il grafico viene assunto l'anno corrente. L'analisi considera al massimo i primi 250.000 eventi del file.
