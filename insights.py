"""Deterministic local rules, evidence and ticket text."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from parsing import UNKNOWN, clean_ip

CATALOG = json.loads((Path(__file__).with_name("catalog.json")).read_text(encoding="utf-8"))
CATEGORIES = {item["id"]: item["label"] for item in CATALOG["categories"]}
CATEGORIES["other"] = "Altri eventi / non classificati"
RULES = [(item["id"], [re.compile(p, re.I) for p in item["patterns"]],
          [re.compile(p, re.I) for p in item.get("exclude", [])]) for item in CATALOG["categories"]]
EVIDENCE_LIMIT = 30


def classify(event):
    message = event["message"]
    context = event["process"] + " " + message
    for category, patterns, exclusions in RULES:
        if any(p.search(message) for p in exclusions):
            continue
        if any(p.search(message) or p.search(context) for p in patterns):
            return category
    return "other"


def message_template(message):
    # Preserve numeric error/status codes; only obvious variable identifiers are masked.
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", message)
    value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<id>", value, flags=re.I)
    value = re.sub(r"(?i)\bpid[=: ]+\d+", "pid=<pid>", value)
    value = re.sub(r"\[\d+\]", "[<pid>]", value)
    return re.sub(r"\s+", " ", value).strip()[:300] or "(messaggio vuoto)"


def extract_network(event):
    """Only labeled addresses are endpoints; HostIP is never treated as a remote peer."""
    message = event["message"]
    values = {}
    for field, names in (("src", "src|src_ip|source_ip|saddr"),
                         ("dst", "dst|dst_ip|destination_ip|daddr")):
        match = re.search(rf"\b(?:{names})\s*[=:]\s*([0-9a-fA-F:.]+)", message, re.I)
        values[field] = clean_ip(match[1]) if match else ""
    if not values["src"] and event["category"] in ("auth_failure", "auth_success"):
        match = re.search(r"\bfrom\s+([0-9a-fA-F:.]+)", message)
        values["src"] = clean_ip(match[1]) if match else ""
    for field, names in (("src_port", "spt|sport|src_port"), ("dst_port", "dpt|dport|dst_port")):
        match = re.search(rf"\b(?:{names})\s*[=:]\s*(\d+)\b", message, re.I)
        values[field] = int(match[1]) if match and 0 <= int(match[1]) <= 65535 else None
    match = re.search(r"\b(?:user|username|account)\s*[=:]\s*([^\s,;]+)", message, re.I)
    if not match:
        match = re.search(r"\b(?:Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+)", message, re.I)
    values["user"] = match[1].strip("\"'") if match else ""
    host_ip = clean_ip(event["host_ip"])
    values["direction"] = "unknown"
    if host_ip and values["src"] == host_ip and values["dst"] and values["dst"] != host_ip:
        values["direction"] = "outbound"
    elif host_ip and values["dst"] == host_ip and values["src"] and values["src"] != host_ip:
        values["direction"] = "inbound"
    return values


def lifecycle(event):
    message = event["message"]
    if re.search(r"\b(?:failed|failure|not started|already|stopped|fallito)\b", message, re.I):
        return None
    match = re.search(r"^(Started|Starting|Avviato|Avvio)\s+(.+?)(?:\.$|$)", message, re.I)
    if match and event["process"] in ("systemd", "init"):
        return {"target": match[2][:100], "match_process": match[2].split()[0], "target_pid": "",
                "status": "avvio richiesto" if match[1].lower() in ("starting", "avvio") else "avvio segnalato"}
    pattern = r"\b(?:process|service|daemon|server|processo|servizio)\b.{0,60}\b(?:started|launched|avviat[oa])\b"
    if re.search(pattern, message, re.I) or re.match(r"^(?:started|avviato)\b", message, re.I):
        if event["process"] != UNKNOWN:
            return {"target": event["process"], "match_process": event["process"],
                    "target_pid": event["pid"], "status": "avvio segnalato"}
    return None


def evidence(event):
    return {"row": event["row"], "line": event["line"], "time": event["timestamp"],
            "host": event["host"], "host_ip": event["host_ip"], "process": event["process"],
            "pid": event["pid"], "facility": event["facility"], "severity": event["severity"],
            "category": event["category"], "message": event["message"][:2000],
            "raw": event["raw"][:2000], "text_truncated": len(event["raw"]) > 2000 or len(event["message"]) > 2000,
            "columns": {key: value[:2000] for key, value in event.get("columns", {}).items()},
            "network": event["network"]}


def distribution(counts, total, labels=None, limit=None):
    return [{"name": key, "label": (labels or {}).get(key, key), "count": count,
             "percent": round(count * 100 / total, 2) if total else 0}
            for key, count in counts.most_common(limit)]


def hypotheses(events, baseline_categories):
    total = len(events)
    categories = Counter(e["category"] for e in events)
    previous_total = sum(baseline_categories.values())
    suggestions = []
    for cause in CATALOG["causes"]:
        if cause["id"] == "unknown":
            continue
        matching = [e for e in events if e["category"] in cause["categories"]]
        count = len(matching)
        share = 100 * count / total if total else 0
        if count < cause["min_count"] or share < cause["min_percent"]:
            continue
        gate = cause.get("gate")
        gate_reason = ""
        if gate == "auth_peer":
            sources = Counter(e["network"]["src"] for e in matching if e["network"]["src"])
            if not sources or sources.most_common(1)[0][1] < 5:
                continue
            peer, attempts = sources.most_common(1)[0]
            gate_reason = f"{attempts} fallimenti con sorgente esplicita {peer}."
        elif gate == "service_failure":
            if categories["service_failure"] < 2:
                continue
            gate_reason = f"{categories['service_failure']} errori/riavvii di servizio."
        elif gate == "scan_evidence":
            outgoing = [e for e in matching if e["network"]["direction"] == "outbound"]
            destinations = {e["network"]["dst"] for e in outgoing if e["network"]["dst"]}
            ports = {e["network"]["dst_port"] for e in outgoing if e["network"]["dst_port"] is not None}
            if categories["scan_alert"] >= 3:
                gate_reason = f"{categories['scan_alert']} segnalazioni esplicite di scansione."
            elif len(outgoing) >= 10 and (len(destinations) >= 10 or len(ports) >= 10):
                gate_reason = f"{len(outgoing)} eventi in uscita, {len(destinations)} destinazioni e {len(ports)} porte distinte."
            else:
                continue
        previous = sum(baseline_categories[c] for c in cause["categories"])
        before = 100 * previous / previous_total if previous_total else None
        refs = [{"id": technique, **CATALOG["mitre"][technique]} for technique in cause.get("mitre", [])]
        suggestions.append({**cause, "count": count, "percent": round(share, 2),
                            "baseline_percent": round(before, 2) if before is not None else None,
                            "delta_pp": round(share - before, 2) if before is not None else None,
                            "reason": f"{count}/{total} eventi ({share:.1f}%). Regola: almeno {cause['min_count']} eventi e {cause['min_percent']}%. {gate_reason}".strip(),
                            "support": "componente dominante" if share >= 60 else "contributo parziale",
                            "evidence_rows": [e["row"] for e in matching[:5]], "mitre_refs": refs})
    return sorted(suggestions, key=lambda s: (-s["percent"], s["id"]))


def auth_sequences(events):
    attempts = defaultdict(list)
    chains = []
    for event in sorted(events, key=lambda e: (e["epoch"], e["row"])):
        net = event["network"]
        if not net["src"] or not net["user"]:
            continue
        key = (net["src"], net["user"])
        if event["category"] == "auth_failure":
            attempts[key].append(event)
        elif event["category"] == "auth_success" and len(attempts[key]) >= 3:
            failures = attempts.pop(key)
            chains.append({"label": "Fallimenti seguiti da accesso riuscito",
                           "source": key[0], "user": key[1], "failures": len(failures),
                           "from": failures[0]["timestamp"], "to": event["timestamp"],
                           "rows": [e["row"] for e in failures[:4]] + [event["row"]],
                           "note": "Stesso host, IP sorgente e utente nella finestra; verificare se l'accesso era autorizzato."})
    return chains[:10]


def markdown_ticket(incident, filename, file_hash, quality):
    history_lines = [
        "- Storico macchina: incluso (finestre precedenti dello stesso host nel file importato).",
        f"- Baseline: {incident['baseline']:.2f} eventi/finestra su {incident['baseline_windows']} finestre precedenti.",
        f"- Soglia finale host: {incident['cutoff']} eventi; mediana precedente {incident['median']}, MAD {incident['mad']}."
    ] if incident["use_history"] else [
        "- Storico macchina: escluso. Nessun confronto con finestre precedenti.",
        f"- Soglia assoluta: almeno {incident['cutoff']} eventi nella finestra. Non dimostra uno spike relativo al passato."
    ]
    lines = [f"# Analisi eventi syslog — {incident['host']} — {incident['time']}",
             "", "Stato: bozza da verificare",
             "Causa selezionata: da determinare", "",
             "## Osservazioni",
             f"- File: {filename}", f"- SHA-256 UTF-8 del contenuto analizzato: {file_hash}",
             f"- Host: {incident['host']}; HostIP: {', '.join(incident['host_ips']) or 'non disponibile'}",
             f"- Finestra UTC: [{incident['time']}, {incident['end']})",
             f"- {incident['count']} eventi; classificazione: {incident['kind']}.",
             *history_lines,
             f"- Processi: {', '.join(p['name'] + ' (' + str(p['count']) + ')' for p in incident['processes'])}.",
             "- Le percentuali seguenti hanno come denominatore tutti gli eventi di questo host nella finestra.",
             "", "## Tipi di eventi"]
    lines += [f"- {c['label']}: {c['count']}/{incident['count']} ({c['percent']}%)." for c in incident["categories"]]
    for proc in incident["processes"]:
        if proc["detected"]:
            lines.append(f"- Spike processo {proc['name']}: {proc['count']} eventi; baseline {proc['baseline']}, "
                         f"soglia {proc['cutoff']}, {proc['baseline_windows']} finestre di confronto.")
    lines += ["", "## Contesto della finestra",
              "- Facility: " + ", ".join(f"{c['name']} ({c['count']})" for c in incident["facilities"]),
              "- Livelli: " + ", ".join(f"{c['name']} ({c['count']})" for c in incident["severities"]),
              f"- Endpoint espliciti in {incident['network']['with_endpoints']} eventi; "
              f"{incident['network']['distinct_destinations']} destinazioni e {incident['network']['distinct_ports']} porte distinte.",
              "- Direzione: " + (", ".join(f"{c['name']} ({c['count']})" for c in incident["network"]["directions"]) or "non determinabile"),
              "- IP destinazione espliciti (primi 10): " + (", ".join(f"{c['name']} ({c['count']})" for c in incident["network"]["destinations"]) or "non disponibili")]
    lines += ["", "## Ipotesi suggerite (non confermate)"]
    if not incident["suggestions"]:
        lines.append("- Nessuna regola supera le soglie; causa da determinare.")
    for suggestion in incident["suggestions"]:
        lines += [f"- {suggestion['title']}: {suggestion['reason']}"]
        if suggestion["delta_pp"] is not None:
            lines.append(f"  Quota precedente {suggestion['baseline_percent']}%; variazione {suggestion['delta_pp']:+.2f} punti percentuali.")
        for ref in suggestion["mitre_refs"]:
            lines.append(f"  MITRE candidato {ref['id']} — {ref['name']}: {ref['url']}. Da validare: {ref['condition']}")
        lines += [f"  Verifica: {check}" for check in suggestion["checks"]]
    if incident["sequences"]:
        lines += ["", "## Sequenze osservate"]
        for sequence in incident["sequences"]:
            lines.append(f"- {sequence['label']}: sorgente {sequence['source']}, utente {sequence['user']}, "
                         f"{sequence['failures']} fallimenti; righe {sequence['rows']}. {sequence['note']}")
    lines += ["", "## Evidenze (campione)", "I numeri di record sono riferimenti all'input; il testo qui sotto proviene dai log."]
    for item in incident["evidence"]:
        lines += [f"- Record {item['row']}, riga finale {item['line']}, {item['time']}, "
                  f"{item['process']} [{item['severity']}], facility {item['facility']}:",
                  "> " + item["raw"].replace("\r", "").replace("\n", "\n> ")]
    lines += ["", "## Limiti e verifiche richieste",
              "- I conteggi misurano eventi di log, non byte/pacchetti, banda o probabilità di compromissione.",
              "- HostIP identifica l'host del record; SRC/DST vengono estratti solo quando espliciti nel messaggio.",
              "- Confermare il picco con contatori di interfaccia, firewall, proxy o NetFlow e verificare la direzione.",
              ("- Le finestre senza eventi sono trattate come zero: verificare continuità della raccolta e cambi del livello di logging."
               if incident["use_history"] else "- Confronto storico disattivato: quote e ipotesi riguardano solo la finestra selezionata."),
              f"- Timestamp senza fuso interpretati come {quality['naive_offset']}; date con slash: {quality['date_order']}.",
              f"- Qualità input: {json.dumps(quality['counts'], ensure_ascii=False)}; limite eventi raggiunto: {quality['truncated']}.",
              f"- Import: {quality['summary']['analyzed_records']} record analizzati su {quality['summary']['records_read']} esaminati; "
              f"{quality['summary']['skipped_records']} esclusi per struttura CSV non valida.",
              f"- Evidenze mostrate {len(incident['evidence'])}/{incident['count']}; i testi oltre 2000 caratteri sono troncati.",
              f"- Catalogo locale {CATALOG['version']}; MITRE consultato il {CATALOG['mitre_reviewed']}.",
              "", "## Impatto e note dell'analista", "Da completare: impatto misurato, verifiche effettuate, esito e responsabile."]
    return "\n".join(lines) + "\n"
