"""Host-scoped spike analysis, bounded timelines and ticket dossiers."""
from __future__ import annotations

import hashlib
import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import median

from insights import (CATALOG, CATEGORIES, EVIDENCE_LIMIT, auth_sequences, classify, distribution,
                      evidence, extract_network, hypotheses, lifecycle, markdown_ticket, message_template)
from parsing import UNKNOWN, read_events

LOOKBACK = 12
MIN_BASELINE = 3
MAX_INCIDENTS = 50


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def baseline(counter, bucket, beginning, seconds, threshold, minimum):
    count = counter.get(bucket, 0)
    previous = [counter.get(bucket - offset * seconds, 0)
                for offset in range(1, LOOKBACK + 1) if bucket - offset * seconds >= beginning]
    mean = sum(previous) / len(previous) if previous else 0
    center = median(previous) if previous else 0
    mad = median([abs(value - center) for value in previous]) if previous else 0
    # Both guards apply: relative increase and robust deviation from recent activity.
    cutoff = max(minimum, math.ceil(mean * threshold), math.floor(center + 3 * 1.4826 * mad) + 1)
    detected = len(previous) >= MIN_BASELINE and count >= cutoff and count > mean
    return {"baseline": round(mean, 3), "baseline_windows": len(previous),
            "median": center, "mad": mad, "cutoff": cutoff, "detected": detected,
            "ratio": round(count / mean, 2) if mean else None}


def temporal_tree(events, seconds):
    known = [e for e in events if e["epoch"] is not None and not e["host_key"].startswith("unknown-row-")]
    ordered = sorted(known, key=lambda e: (e["epoch"], e["row"]))
    hosts, processes = defaultdict(list), defaultdict(list)
    starts = []
    observed = {}
    explicit_keys = set()
    for event in ordered:
        key = (event["host_key"], event["process"], event["pid"])
        hosts[event["host_key"]].append(event)
        processes[(event["host_key"], event["process"])].append(event)
        observed.setdefault(key, event)
        start = lifecycle(event)
        if start:
            starts.append((event, start))
            explicit_keys.add((event["host_key"], start["match_process"], start["target_pid"]))
    for key, event in observed.items():
        if key not in explicit_keys and (key[0], key[1], "") not in explicit_keys and event["process"] != UNKNOWN:
            starts.append((event, {"target": event["process"], "match_process": event["process"],
                                  "target_pid": event["pid"], "status": "prima osservazione; avvio non dimostrato"}))
    host_keys = {host: [(e["epoch"], e["row"]) for e in rows] for host, rows in hosts.items()}
    proc_keys = {key: [(e["epoch"], e["row"]) for e in rows] for key, rows in processes.items()}
    output = []
    for start, info in sorted(starts, key=lambda pair: (pair[0]["epoch"], pair[0]["row"]))[-100:]:
        proc_key = (start["host_key"], info["match_process"])
        same = processes.get(proc_key, [])
        keys = proc_keys.get(proc_key, [])
        lo = bisect_right(keys, (start["epoch"], start["row"]))
        hi = bisect_right(keys, (start["epoch"] + 1800, float("inf")))
        children = []
        child_total = 0
        for index in range(lo, hi):
            event = same[index]
            if info["target_pid"] and event["pid"] and info["target_pid"] != event["pid"]:
                continue
            if lifecycle(event):
                break
            child_total += 1
            if len(children) < 20:
                children.append(evidence(event))
        host_rows = hosts[start["host_key"]]
        keys = host_keys[start["host_key"]]
        lo = bisect_left(keys, (start["epoch"] - seconds, -1))
        hi = bisect_right(keys, (start["epoch"] + seconds, float("inf")))
        # Select nearest events from each side without sorting/scanning a whole large host window.
        pivot = bisect_left(keys, (start["epoch"], start["row"]))
        left, right = pivot - 1, pivot
        nearby = []
        inspected = 0
        while (left >= lo or right < hi) and len(nearby) < 10 and inspected < 2000:
            if right >= hi or (left >= lo and start["epoch"] - host_rows[left]["epoch"] <= host_rows[right]["epoch"] - start["epoch"]):
                event = host_rows[left]
                left -= 1
            else:
                event = host_rows[right]
                right += 1
            inspected += 1
            if event is start or event["process"] in (UNKNOWN, info["match_process"], start["process"]):
                continue
            nearby.append({**evidence(event), "delta_seconds": round(event["epoch"] - start["epoch"]),
                           "relation": "stesso host e vicinanza temporale"})
        output.append({**evidence(start), **info, "process_events": children,
                       "process_events_total": child_total, "nearby_events": nearby,
                       "nearby_scan_limited": inspected == 2000})
    return output, len(starts)


def correlations(events, seconds):
    fields = {"process_facility": "facility", "process_severity": "severity", "process_host_ip": "host_ip"}
    totals = Counter((e["host_key"], e["process"]) for e in events)
    result = {}
    for name, field in fields.items():
        counts = Counter((e["host_key"], e["process"], e[field]) for e in events
                         if e["process"] != UNKNOWN and e[field] != UNKNOWN and not e["host_key"].startswith("unknown-row-"))
        result[name] = [{"host": host, "process": proc, "value": value, "count": count,
                         "process_share": round(100 * count / totals[(host, proc)], 2)}
                        for (host, proc, value), count in counts.most_common(20)]
    active = defaultdict(set)
    for event in events:
        if event["epoch"] is not None and event["process"] != UNKNOWN and not event["host_key"].startswith("unknown-row-"):
            active[(event["host_key"], event["process"])].add(int(event["epoch"] // seconds) * seconds)
    top_by_host = defaultdict(list)
    for key in sorted(active, key=lambda key: (-totals[key], key)):
        if len(top_by_host[key[0]]) < 20:
            top_by_host[key[0]].append(key[1])
    pairs = []
    for host, procs in top_by_host.items():
        for index, first in enumerate(procs):
            for second in procs[index + 1:]:
                a, b = active[(host, first)], active[(host, second)]
                shared = len(a & b)
                if shared >= 2:
                    pairs.append({"host": host, "first": first, "second": second,
                                  "shared_windows": shared, "jaccard": round(shared / len(a | b), 3)})
    result["process_cooccurrence"] = sorted(pairs, key=lambda p: (-p["shared_windows"], -p["jaccard"]))[:20]
    return result


def build_incident(host, bucket, events, stats, contributors, buckets, seconds, filename, file_hash, quality):
    total = len(events)
    category_counts = Counter(e["category"] for e in events)
    previous_categories = Counter()
    for offset in range(1, LOOKBACK + 1):
        previous_categories.update(e["category"] for e in buckets.get((host, bucket - offset * seconds), []))
    suggestions = hypotheses(events, previous_categories)
    by_row = {e["row"]: e for e in events}
    # Include evidence for every displayed rule, even if its events occurred after the first 30.
    chosen = {}
    sequences = auth_sequences(events)
    for item in suggestions + sequences:
        for row in item.get("evidence_rows", item.get("rows", [])):
            if row in by_row and len(chosen) < EVIDENCE_LIMIT:
                chosen[row] = by_row[row]
    for event in events:
        if len(chosen) >= EVIDENCE_LIMIT:
            break
        chosen.setdefault(event["row"], event)
    network = [e for e in events if e["network"]["src"] or e["network"]["dst"]]
    incident = {"id": hashlib.sha256(f"{host}|{bucket}".encode()).hexdigest()[:16],
                "host": host, "host_ips": sorted({e["host_ip"] for e in events if e["host_ip"] != UNKNOWN}),
                "time": iso(bucket), "end": iso(bucket + seconds), "count": total, **stats,
                "kind": "spike host" if stats["detected"] else (
                    "spike processo" if any(p["detected"] for p in contributors) else "finestra da esaminare; spike non dimostrato"),
                "processes": contributors,
                "categories": distribution(category_counts, total, CATEGORIES),
                "facilities": distribution(Counter(e["facility"] for e in events), total),
                "severities": distribution(Counter(e["severity"] for e in events), total),
                "messages": [{"message": item["name"], **item} for item in distribution(
                    Counter(e["template"] for e in events), total, limit=10)],
                "network": {"with_endpoints": len(network),
                            "directions": distribution(Counter(e["network"]["direction"] for e in network), len(network)),
                            "sources": distribution(Counter(e["network"]["src"] for e in network if e["network"]["src"]), total, limit=10),
                            "destinations": distribution(Counter(e["network"]["dst"] for e in network if e["network"]["dst"]), total, limit=10),
                            "distinct_destinations": len({e["network"]["dst"] for e in network if e["network"]["dst"]}),
                            "distinct_ports": len({e["network"]["dst_port"] for e in network if e["network"]["dst_port"] is not None})},
                "suggestions": suggestions, "sequences": sequences,
                "evidence": [evidence(e) for e in sorted(chosen.values(), key=lambda e: (e["epoch"], e["row"]))]}
    incident["ticket"] = markdown_ticket(incident, filename, file_hash, quality)
    return incident


def analyze(content: str, filename: str, window_minutes=5, threshold=2.0,
            min_events=5, naive_offset="+00:00", date_order="DMY") -> dict:
    if not isinstance(content, str) or not isinstance(filename, str):
        raise ValueError("Contenuto e nome del file devono essere testo.")
    if not 1 <= window_minutes <= 1440 or int(window_minutes) != window_minutes:
        raise ValueError("La finestra deve essere un intero tra 1 e 1440 minuti.")
    if not math.isfinite(threshold) or not 1.1 <= threshold <= 100:
        raise ValueError("Il moltiplicatore deve essere tra 1.1 e 100.")
    if not 3 <= min_events <= 100_000 or int(min_events) != min_events:
        raise ValueError("Il minimo deve essere un intero tra 3 e 100000 eventi.")
    seconds = int(window_minutes) * 60
    rows, quality = read_events(content, filename, naive_offset, date_order)
    file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    enrichment_cache = {}
    for event in rows:
        signature = (event["process"], event["message"], event["host_ip"])
        cached = enrichment_cache.get(signature)
        if cached is None:
            event["category"] = classify(event)
            cached = (event["category"], message_template(event["message"]), extract_network(event))
            if len(enrichment_cache) < 4096:
                enrichment_cache[signature] = cached
        event["category"], event["template"], event["network"] = cached
    timed = sorted((e for e in rows if e["epoch"] is not None), key=lambda e: (e["epoch"], e["row"]))
    buckets = defaultdict(list)
    host_counts, proc_counts = defaultdict(Counter), defaultdict(Counter)
    host_begin = {}
    all_counts = Counter()
    for event in timed:
        bucket = int(event["epoch"] // seconds) * seconds
        all_counts[bucket] += 1
        if event["host_key"].startswith("unknown-row-"):
            continue
        host = event["host_key"]
        host_begin.setdefault(host, bucket)
        buckets[(host, bucket)].append(event)
        host_counts[host][bucket] += 1
        proc_counts[(host, event["process"])][bucket] += 1
    candidates = []
    peaks = {}
    for (host, bucket), events in buckets.items():
        stats = baseline(host_counts[host], bucket, host_begin[host], seconds, threshold, min_events)
        processes = Counter(e["process"] for e in events)
        contributors = []
        for proc, count in processes.most_common():
            proc_stats = baseline(proc_counts[(host, proc)], bucket, host_begin[host], seconds, threshold, min_events)
            if proc == UNKNOWN:
                proc_stats["detected"] = False
            contributors.append({"name": proc, "count": count, "percent": round(100 * count / len(events), 2), **proc_stats})
        candidate = (host, bucket, events, stats, contributors)
        if stats["detected"] or any(p["detected"] for p in contributors):
            candidates.append(candidate)
        if host not in peaks or len(events) > len(peaks[host][2]):
            peaks[host] = candidate
    hosts_with_spikes = {candidate[0] for candidate in candidates}
    candidates += [peak for host, peak in peaks.items() if host not in hosts_with_spikes]
    candidates.sort(key=lambda c: (
        -(c[3]["detected"] or any(p["detected"] for p in c[4])),
        -(len(c[2]) - c[3]["baseline"]), -len(c[2]), c[0], c[1]))
    incidents = [build_incident(*candidate, buckets, seconds, filename, file_hash, quality)
                 for candidate in candidates[:MAX_INCIDENTS]]
    tree, tree_total = temporal_tree(rows, seconds)
    chart = []
    chart_seconds = seconds
    if all_counts:
        start, end = min(all_counts), max(all_counts)
        bins = (end - start) // seconds + 1
        chart_seconds = seconds * max(1, math.ceil(bins / 600))
        compressed = Counter()
        for bucket, count in all_counts.items():
            compressed[(bucket - start) // chart_seconds] += count
        chart = [{"time": iso(start + index * chart_seconds), "count": compressed[index]}
                 for index in range((end - start) // chart_seconds + 1)]
    total = len(rows)
    processes = Counter(e["process"] for e in rows)
    process_messages = defaultdict(Counter)
    for event in rows:
        process_messages[event["process"]][event["template"]] += 1
    spike_count = sum(c[3]["detected"] or any(p["detected"] for p in c[4]) for c in candidates)
    warnings = []
    warning_labels = {"invalid_timestamp": "timestamp non riconosciuti", "missing_timestamp": "timestamp mancanti",
                      "assumed_timezone": f"timestamp senza fuso, interpretati come {naive_offset}",
                      "inferred_year": "date senza anno, assunto l'anno corrente UTC",
                      "missing_host": "host mancanti (correlati solo se HostIP valido)",
                      "missing_process": "processi mancanti", "missing_message": "messaggi mancanti",
                      "identical_records": "record identici già osservati, conservati: verificare eventuali duplicazioni dell'export",
                      "extra_csv_fields": "record con colonne in eccesso", "missing_csv_fields": "record con colonne mancanti",
                      "invalid_host_ip": "HostIP non validi"}
    warnings += [f"{count} {warning_labels.get(key, key)}." for key, count in quality["counts"].items() if count]
    if quality["mapping"]:
        missing = [name for name in ("timestamp", "host", "facility", "severity", "message", "process", "host_ip")
                   if not quality["mapping"].get(name)]
        if missing:
            warnings.append("Colonne non mappate: " + ", ".join(missing) + ".")
    if quality["truncated"]:
        warnings.append(f"Input limitato ai primi {quality['event_limit']} eventi; i conteggi sono parziali.")
    if len(candidates) > MAX_INCIDENTS:
        warnings.append(f"Mostrati {MAX_INCIDENTS}/{len(candidates)} dossier, ordinati per anomalia ed eccesso di eventi.")
    quality["warnings"] = warnings
    return {"total": total, "process_count": sum(p != UNKNOWN for p in processes), "parsed": total - processes[UNKNOWN],
            "with_timestamp": len(timed), "quality": quality,
            "source": {"filename": filename, "sha256": file_hash}, "catalog_version": CATALOG["version"],
            "parameters": {"window_minutes": window_minutes, "threshold": threshold, "min_events": min_events,
                           "lookback": LOOKBACK, "minimum_baseline_windows": MIN_BASELINE},
            "spike_count": spike_count, "incident_count": len(candidates), "incidents": incidents,
            "processes": [{"name": p, "count": count, "percent": round(100 * count / total, 2) if total else 0,
                           "messages": [{"message": msg, "count": num} for msg, num in process_messages[p].most_common(5)]}
                          for p, count in processes.most_common(30)],
            "messages": [{"message": item["name"], **item} for item in distribution(Counter(e["template"] for e in rows), total, limit=15)],
            "categories": distribution(Counter(e["category"] for e in rows), total, CATEGORIES),
            "severities": distribution(Counter(e["severity"] for e in rows), total),
            "hosts": distribution(Counter(e["host_key"] for e in rows if not e["host_key"].startswith("unknown-row-")), total, limit=20),
            "facilities": distribution(Counter(e["facility"] for e in rows), total),
            "host_ips": distribution(Counter(e["host_ip"] for e in rows if e["host_ip"] != UNKNOWN), total, limit=20),
            "correlations": correlations(rows, seconds), "temporal_tree": tree, "temporal_tree_total": tree_total,
            "chart": chart, "chart_seconds": chart_seconds, "cause_catalog": CATALOG["causes"],
            "window_minutes": window_minutes}
