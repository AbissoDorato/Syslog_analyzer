<<<<<<< HEAD
# Syslog Analyser

Analizzatore locale per eventi Linux/syslog con una dashboard per individuare i processi più attivi, i messaggi ricorrenti e gli spike temporali.

## Avvio

1. Installa Python 3.10 o successivo, se non è già disponibile.
2. Fai doppio clic su `Avvia Syslog Analyser.bat`, oppure apri PowerShell in questa cartella ed esegui `python app.py`.
3. La pagina si apre su `http://127.0.0.1:8765`. Per fermare il servizio, chiudi la finestra del terminale o premi `Ctrl+C`.

Non servono pacchetti Python, account, connessione Internet o servizi esterni. Il server ascolta esclusivamente sull’interfaccia di loopback (`127.0.0.1`). Il file viene letto dalla pagina e inviato all’API locale in memoria; non viene salvato dal programma.

## Importazione e risultati

Trascina nella pagina un file `.txt`, `.log` o `.csv` (massimo 30 MB). Per i file di testo, ogni riga non vuota è trattata come un evento. Sono riconosciuti i formati syslog RFC 3164 e RFC 5424, righe ISO con `host processo[pid]: messaggio` e righe journal con data, host e processo. Le righe non riconosciute restano comunque conteggiate e visibili come processo `unknown`.

Per i CSV si cerca una colonna messaggio (`message`, `msg`, `event`, `log`, `content`, `description` o `testo`) e colonne comuni per timestamp, host, processo, PID e severità. Se il CSV ha intestazioni differenti, i campi possono comunque essere rappresentati nel messaggio aggregato.

La schermata mostra i conteggi per processo, la severità, gli host più attivi e i messaggi ricorrenti. Numeri e identificativi nel testo vengono normalizzati nell’aggregazione, così eventi simili finiscono nello stesso gruppo. Selezionando un processo si vedono i suoi messaggi più frequenti.

Gli spike sono calcolati per finestre temporali configurabili. Una finestra viene segnalata se contiene almeno 3 eventi e supera la media delle finestre di quel processo del moltiplicatore impostato. Il confronto include gli intervalli senza eventi quando l’intervallo complessivo è entro 20.000 finestre. I log senza timestamp restano analizzabili per conteggi e processi, ma non possono contribuire al grafico temporale o ai picchi.

## Limiti

Il parser usa euristiche leggere e non conosce tutti i formati personalizzati di syslog, auditd o applicazioni. Verifica i nomi delle colonne CSV se i processi non vengono attribuiti correttamente. Le date RFC 3164 non contengono l’anno: per il grafico viene assunto l’anno corrente. L’analisi opera al massimo sui primi 250.000 eventi del file.
=======
# Syslog_analyzer
Analyzer of syslog
>>>>>>> origin/main
