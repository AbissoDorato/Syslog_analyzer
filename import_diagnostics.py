"""Bounded, actionable import diagnostics; distinct from SyslogMessage severity."""
from collections import Counter

SAMPLE_LIMIT = 5
FIELD_NAMES = {"timestamp": "TimeGenerated", "host": "Computer", "host_ip": "HostIP",
               "process": "ProcessName", "message": "SyslogMessage", "severity": "SecurityLevel / Seceritylevel",
               "facility": "Facility", "pid": "ProcessID", "event_time": "EventTime",
               "tenant_id": "TenantId", "source_system": "SourceSystem", "management_group": "MG",
               "hostname": "Hostname", "collector_host_name": "CollectorHostName", "type": "Type"}
# level, field, title, impact, correction
ISSUES = {
    "invalid_timestamp": ("error", "timestamp", "Data/ora non riconosciuta",
        "Il record resta nei conteggi ma non entra nelle finestre temporali.",
        "Usa ISO 8601, per esempio 2026-10-05T10:30:00Z; verifica l'ordine giorno/mese."),
    "invalid_event_time": ("error", "event_time", "EventTime non riconosciuto",
        "EventTime non è utilizzabile; il timestamp di riferimento TimeGenerated resta invariato.",
        "Correggi EventTime usando una data valida, preferibilmente ISO 8601 con suffisso Z."),
    "missing_timestamp": ("warning", "timestamp", "Data/ora mancante",
        "Il record non può contribuire a spike, sequenze o albero temporale.",
        "Esporta TimeGenerated[UTC], EventTime[UTC] o un timestamp nel messaggio syslog."),
    "assumed_timezone": ("info", "timestamp", "Fuso orario assunto",
        "Il valore e la colonna non indicano un fuso: è applicato l'offset scelto nelle impostazioni.",
        "Verifica il fuso del sistema sorgente oppure esporta timestamp con offset esplicito."),
    "column_utc": ("info", "timestamp", "UTC dichiarato nell'intestazione",
        "Il valore senza fuso è interpretato in UTC perché la colonna contiene [UTC]. L'offset nelle impostazioni non si applica.",
        "Nessuna correzione richiesta se l'intestazione descrive correttamente i dati."),
    "timezone_conflict": ("warning", "timestamp", "Offset diverso da UTC in una colonna [UTC]",
        "È rispettato l'offset esplicito nel valore e l'istante viene convertito in UTC.",
        "Controlla l'export: rendi coerenti il nome della colonna e il fuso del valore."),
    "event_time_fallback": ("info", "timestamp", "EventTime scelto come riferimento",
        "TimeGenerated è assente o vuoto: EventTime viene usato per le finestre e le correlazioni se valido.",
        "Controlla che EventTime sia il riferimento desiderato; valorizza TimeGenerated per dare priorità a quel campo."),
    "ambiguous_date": ("warning", "timestamp", "Data con giorno e mese ambigui",
        "La data è interpretata secondo l'ordine DMY/MDY selezionato.",
        "Controlla l'impostazione delle date con slash; preferisci un export ISO 8601."),
    "inferred_year": ("info", "timestamp", "Anno assente",
        "È assunto l'anno corrente UTC.",
        "Esporta le date complete, soprattutto per log storici o a cavallo di Capodanno."),
    "missing_host": ("warning", "host", "Nome della macchina mancante",
        "È usato HostIP se valido; altrimenti il record non entra nei dossier per host.",
        "Esporta Computer o un HostIP valido."),
    "missing_process": ("warning", "process", "Processo non identificato",
        "Il record rimane nei totali ma non identifica un processo nell'albero.",
        "Esporta Processname o il tag processo nel messaggio syslog."),
    "missing_message": ("warning", "message", "Messaggio vuoto",
        "Non ci sono contenuti per classificare la causa.",
        "Verifica SyslogMessage e le opzioni di esportazione."),
    "invalid_host_ip": ("error", "host_ip", "Indirizzo IP non valido",
        "L'indirizzo non viene usato per dedurre la direzione delle connessioni.",
        "Inserisci un singolo indirizzo IPv4/IPv6, senza porta, etichette o subnet CIDR."),
    "unrecognized_severity": ("warning", "severity", "Livello syslog non standard",
        "Il valore è conservato come etichetta personalizzata.",
        "Verifica SecurityLevel: usa un livello syslog o un numero tra 0 e 7."),
    "unrecognized_facility": ("warning", "facility", "Facility non standard",
        "Il valore è conservato come etichetta personalizzata.",
        "Verifica Facility: usa un nome syslog o un numero tra 0 e 23."),
    "identical_records": ("warning", "", "Record normalizzati identici",
        "Sono conservati: potrebbero essere eventi distinti o duplicati dell'export.",
        "Controlla doppie esportazioni o duplicazioni nel collettore prima di eliminare record."),
    "extra_csv_fields": ("error", "", "Troppe colonne nel record",
        "Il record è escluso dall'analisi perché i campi possono essere spostati.",
        "Controlla il separatore. Racchiudi tra doppi apici i messaggi che contengono il separatore."),
    "missing_csv_fields": ("error", "", "Colonne insufficienti nel record",
        "Il record è escluso dall'analisi perché la struttura non corrisponde all'intestazione.",
        "Verifica esportazione, separatore e campi vuoti: conserva tutti i delimitatori."),
    "csv_syntax": ("error", "", "Sintassi CSV non valida",
        "Importazione bloccata: non è possibile ricostruire in modo affidabile i record successivi.",
        "Controlla gli apici vicino alle righe indicate; gli apici interni devono essere raddoppiati."),
    "duplicate_headers": ("error", "", "Intestazioni duplicate",
        "Importazione bloccata per evitare la sovrascrittura silenziosa dei valori.",
        "Rinomina o rimuovi le colonne duplicate, anche se differiscono solo per spazi o maiuscole."),
    "unrecognized_columns": ("error", "", "Nessuna colonna riconosciuta",
        "Importazione bloccata: separatore o intestazioni potrebbero essere errati.",
        "Seleziona il separatore corretto e usa le intestazioni TimeGenerated, Computer, SyslogMessage e Processname."),
    "missing_column": ("warning", "", "Colonna attesa assente",
        "Il campo può essere recuperato dal messaggio syslog quando riconoscibile; altrimenti resta mancante.",
        "Verifica le colonne selezionate nell'export e gli alias indicati nel README."),
    "empty_header": ("error", "", "Intestazione vuota",
        "Importazione bloccata: almeno una colonna non ha un nome.",
        "Assegna un nome a ogni colonna o elimina i delimitatori superflui nell'intestazione."),
    "ambiguous_alias": ("warning", "", "Più colonne per lo stesso campo",
        "Viene usata la priorità degli alias; un valore vuoto può usare l'alias successivo.",
        "Mantieni una sola colonna per campo per evitare interpretazioni ambigue."),
    "no_records": ("warning", "", "Nessun record di dati",
        "Non è disponibile alcun evento da analizzare.",
        "Controlla che il file non sia vuoto o composto solo dall'intestazione."),
    "event_limit": ("warning", "", "Limite di record raggiunto",
        "L'analisi è parziale: il resto del file non è stato esaminato.",
        "Aumenta --max-events all'avvio e ricarica il file, oppure suddividi l'export per macchina o intervallo di tempo."),
    "file_too_large": ("error", "", "Contenuto troppo grande",
        "Importazione bloccata: il contenuto UTF-8 supera il limite configurato, indicato nel dettaglio.",
        "Aumenta --max-file-mb all'avvio e ricarica il file, oppure suddividi l'export in intervalli più piccoli."),
    "null_bytes": ("error", "", "Caratteri NUL nel testo",
        "Importazione bloccata: possibile file binario o codifica UTF-16 senza BOM.",
        "Riesporta come CSV UTF-8 o UTF-16 con BOM."),
}


class ImportFailure(ValueError):
    def __init__(self, message, report):
        super().__init__(message)
        self.report = report


class Diagnostics:
    def __init__(self):
        self.items = {}
        self.records_with_issues = set()

    def add(self, code, *, event=None, value=None, record=None, line_start=None, line_end=None, column=None):
        level, field, title, impact, action = ISSUES[code]
        if event is not None:
            record = event["row"]
            line_start = event.get("line_start", event["line"])
            line_end = event["line"]
            if value is None:
                if field in event.get("columns", {}):
                    value = event["columns"][field]
                elif field == "timestamp":
                    value = event.get("input_timestamp", "")
                else:
                    value = event.get(field) if field else event["raw"]
        if record is not None:
            self.records_with_issues.add(record)
        item = self.items.setdefault(code, {"code": code, "level": level, "field": field,
            "title": title, "impact": impact, "action": action, "count": 0, "examples": []})
        item["count"] += 1
        if len(item["examples"]) < SAMPLE_LIMIT:
            item["examples"].append({"record": record, "line_start": line_start, "line_end": line_end,
                                     "column": column or FIELD_NAMES.get(field, ""),
                                     "value": str(value if value is not None else "")[:240]})

    def report(self, base, rows, records_read, skipped, *, blocked=False, complete=True):
        issues = sorted(self.items.values(), key=lambda item: ({"error":0, "warning":1, "info":2}[item["level"]], item["code"]))
        counts = {item["code"]: item["count"] for item in issues}
        severity_counts = Counter()
        for item in issues:
            severity_counts[item["level"]] += item["count"]
        analyzed = 0 if blocked else len(rows)
        status = "blocked" if blocked else "partial" if skipped or base["truncated"] else (
            "empty" if not rows else "warning" if any(item["level"] != "info" for item in issues) else "ok")
        return {**base, "status": status, "counts": counts, "diagnostics": issues,
                "sample_limit": SAMPLE_LIMIT, "severity_counts": dict(severity_counts),
                "warnings": [f"{item['count']} × {item['title']}." for item in issues],
                "summary": {"records_read": records_read, "analyzed_records": analyzed,
                    "skipped_records": skipped, "parsed_before_block": len(rows) if blocked else 0,
                    "records_with_issues": len(self.records_with_issues), "complete": complete,
                    "with_timestamp": sum(e["timestamp"] is not None for e in rows) if not blocked else 0,
                    "usable_for_windows": sum(e["timestamp"] is not None and not e["host_key"].startswith("unknown-row-")
                                              for e in rows) if not blocked else 0}}
