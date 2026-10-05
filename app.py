#!/usr/bin/env python3
"""Offline Linux/syslog event analyser. Uses only the Python standard library."""
from __future__ import annotations

import csv
import io
import json
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
MAX_BODY = 30 * 1024 * 1024
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
RFC5424 = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ver>\d+) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?:\[.*?\]|-) ?(?P<msg>.*)$")
RFC3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<tag>[^:]+):\s?(?P<msg>.*)$")
ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ][0-9:.+Z\-]+)\s+(?P<host>\S+)\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$")
PROC_PID = re.compile(r"^(?P<proc>[\w./:@-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
JOURNAL = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d\d:\d\d:\d\d) (?P<host>\S+) (?P<proc>[\w./:@-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
PROCESS_START = re.compile(r"\b(?:started|starting|start(?:ed)?|launched|launching|spawned|created|initialized|initialised|avviat[oaie]?|avvio|lanciato|creato)\b", re.I)
START_FAILURE = re.compile(r"\b(?:fail(?:ed|ure)?|error|fallit[oa]?|non\s+riuscit[oa])\b", re.I)

def timestamp(value: str | None) -> str | None:
    if not value or value in ("-", "N/A", "null"):
        return None
    value = value.strip()
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.isoformat()
    except ValueError:
        pass
    m = re.match(r"^(\w{3})\s+(\d{1,2}) (\d\d:\d\d:\d\d)$", value)
    if m and m.group(1) in MONTHS:
        # Year is deliberately marked as inferred when absent from the source.
        return datetime(datetime.now().year, MONTHS[m.group(1)], int(m.group(2)), *map(int, m.group(3).split(":"))).isoformat()
    return None

def normalize_row(row: dict) -> dict:
    clean = {str(k or "").lstrip("\ufeff").strip().lower(): str(v or "").strip() for k, v in row.items()}
    def pick(*keys):
        return next((clean[k] for k in keys if clean.get(k)), "")
    raw = pick("message", "msg", "event", "log", "content", "description", "testo", "syslogmessage")
    ts = pick("timestamp", "time", "timegenerated", "datetime", "date", "@timestamp", "data", "ora")
    host = pick("hostname", "host", "computer", "machine")
    proc = pick("process", "process_name", "processname", "program", "application", "app", "comm", "unit", "service")
    pid = pick("pid", "process_id")
    severity = pick("severity", "securitylevel", "level", "priority", "loglevel")
    facility = pick("facility", "syslogfacility") or "unknown"
    host_ip = pick("hostip", "host_ip", "ip", "ipaddress") or "unknown"
    if raw:
        parsed = parse_line(raw)
        return {**parsed, "timestamp": timestamp(ts) or parsed["timestamp"], "host": host or parsed["host"],
                "process": proc or parsed["process"], "pid": pid or parsed["pid"], "severity": severity or parsed["severity"],
                "facility": facility, "host_ip": host_ip, "raw": raw}
    return {"timestamp": timestamp(ts), "host": host or "unknown", "process": proc or "unknown", "pid": pid,
            "severity": severity or "unknown", "facility": facility, "host_ip": host_ip,
            "message": " ".join(f"{k}={v}" for k, v in clean.items() if v), "raw": json.dumps(clean, ensure_ascii=False)}

def parse_line(line: str) -> dict:
    raw = line.strip()
    out = {"timestamp": None, "host": "unknown", "process": "unknown", "pid": "", "severity": "unknown", "facility": "unknown", "host_ip": "unknown", "message": raw, "raw": raw}
    if not raw:
        return out
    m = RFC5424.match(raw)
    if m:
        d = m.groupdict(); pri = int(d["pri"]); out.update(timestamp=timestamp(d["ts"]), host=d["host"], process=d["app"], pid="" if d["pid"] == "-" else d["pid"], severity=severity_from_pri(pri), message=d["msg"]); return out
    m = RFC3164.match(raw)
    if m:
        d = m.groupdict(); out.update(timestamp=timestamp(f"{d['mon']} {d['day']} {d['clock']}"), host=d["host"], message=d["msg"])
        if d["pri"]: out["severity"] = severity_from_pri(int(d["pri"]))
        p = PROC_PID.match(d["tag"].strip())
        if p: out["process"] = p.group("proc"); out["pid"] = p.group("pid") or ""
        else: out["process"] = d["tag"].strip()
        return out
    m = ISO_PREFIX.match(raw)
    if m:
        d = m.groupdict(); out.update(timestamp=timestamp(d["ts"]), host=d["host"], message=d["msg"])
        p = PROC_PID.match(d["tag"].strip())
        if p: out["process"] = p.group("proc"); out["pid"] = p.group("pid") or ""
        else: out["process"] = d["tag"].strip()
        return out
    m = JOURNAL.match(raw)
    if m:
        d = m.groupdict(); out.update(timestamp=timestamp(d["ts"]), host=d["host"], process=d["proc"], pid=d["pid"] or "", message=d["msg"]); return out
    # Common kernel and audit messages don't carry a process tag in a uniform position.
    p = re.search(r"\b(?:kernel|audit|systemd|sudo|sshd|cron|CRON|dbus|NetworkManager)(?:\[(\d+)\])?:", raw)
    if p:
        out["process"] = p.group(0).rstrip(":").split("[")[0]
        out["pid"] = re.search(r"\[(\d+)\]", p.group(0)).group(1) if "[" in p.group(0) else ""
        out["message"] = raw[p.end():].strip()
    return out

def severity_from_pri(pri: int) -> str:
    return ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")[pri % 8]

def analyze(content: str, filename: str, window_minutes: int = 5, threshold: float = 2.0) -> dict:
    is_csv = filename.lower().endswith(".csv")
    lines = content.splitlines()
    rows = []
    if is_csv:
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:8]), delimiters=",;\t|") if lines else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(content), dialect=dialect)
        rows = [normalize_row(row) for row in reader]
    else:
        rows = [parse_line(line) for line in lines if line.strip()]
    rows = rows[:250000]
    proc_counts, severity_counts, host_counts, host_ip_counts, facility_counts, msg_counts = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    proc_facility, proc_severity, proc_host_ip = Counter(), Counter(), Counter()
    proc_messages = defaultdict(Counter)
    timed = defaultdict(Counter)
    process_windows = defaultdict(set)
    temporal_records = []
    for r in rows:
        proc_counts[r["process"]] += 1; severity_counts[r["severity"]] += 1; host_counts[r["host"]] += 1
        host_ip_counts[r.get("host_ip", "unknown")] += 1
        facility_counts[r.get("facility", "unknown")] += 1
        proc_facility[(r["process"], r.get("facility", "unknown"))] += 1
        proc_severity[(r["process"], r["severity"])] += 1
        proc_host_ip[(r["process"], r.get("host_ip", "unknown"))] += 1
        msg = re.sub(r"\b\d+\b", "<n>", r["message"].lower())
        msg = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", msg)
        msg = re.sub(r"\s+", " ", msg).strip()[:180] or "(messaggio vuoto)"
        msg_counts[msg] += 1; proc_messages[r["process"]][msg] += 1
        if r["timestamp"]:
            try:
                dt = datetime.fromisoformat(r["timestamp"])
                epoch = dt.timestamp()
                temporal_records.append({"epoch": epoch, "time": r["timestamp"], "host": r["host"],
                                         "host_ip": r.get("host_ip", "unknown"), "process": r["process"],
                                         "pid": r["pid"], "facility": r.get("facility", "unknown"),
                                         "severity": r["severity"], "message": r["message"][:240]})
                window_seconds = max(1, window_minutes) * 60
                bucket_epoch = int(epoch) // window_seconds * window_seconds
                minute = datetime.fromtimestamp(bucket_epoch, tz=dt.tzinfo)
                timed[(r["process"], minute.isoformat())]["count"] += 1
                timed[("__all__", minute.isoformat())]["count"] += 1
                process_windows[r["process"]].add(minute.isoformat())
            except ValueError: pass
    series = defaultdict(list)
    observed_times = sorted({when for (proc, when) in timed if proc != "__all__"})
    if observed_times:
        start = datetime.fromisoformat(observed_times[0]); end = datetime.fromisoformat(observed_times[-1])
        seconds = max(1, window_minutes) * 60
        bins = int((end.timestamp() - start.timestamp()) // seconds) + 1
        # Fill quiet intervals so an isolated burst is compared with real zero-event windows.
        # Very long exports stay bounded in memory; their observed buckets are retained.
        if bins <= 20000:
            axis = [datetime.fromtimestamp(start.timestamp() + i * seconds, tz=start.tzinfo).isoformat() for i in range(bins)]
            procs = {proc for proc, when in timed if proc != "__all__"}
            for proc in procs:
                for when in axis:
                    series[proc].append({"time": when, "count": timed[(proc, when)]["count"]})
            for when in axis:
                series["__all__"].append({"time": when, "count": timed[("__all__", when)]["count"]})
        else:
            for (proc, when), vals in timed.items(): series[proc].append({"time": when, "count": vals["count"]})
    for proc in series: series[proc].sort(key=lambda p: p["time"])
    spikes = []
    for proc, points in series.items():
        vals = [p["count"] for p in points]
        baseline = sum(vals) / len(vals) if vals else 0
        for point in points:
            if point["count"] >= max(3, baseline * threshold) and point["count"] > baseline:
                spikes.append({"process": "Tutti i processi" if proc == "__all__" else proc, "time": point["time"], "count": point["count"], "baseline": round(baseline, 2), "ratio": round(point["count"] / baseline, 1) if baseline else None, "top_messages": [{"message": m, "count": n} for m,n in proc_messages[proc].most_common(3)] if proc != "__all__" else []})
    spikes.sort(key=lambda s: s["count"], reverse=True)
    def top_associations(counts):
        return [{"process": proc, "value": value, "count": count,
                 "process_share": round(count * 100 / proc_counts[proc], 1) if proc_counts[proc] else 0}
                for (proc, value), count in counts.most_common(20) if proc != "unknown" and value != "unknown"]

    # Same-window co-occurrence indicates temporal overlap only, not a causal relationship.
    active_processes = sorted((p for p in process_windows if p != "unknown"), key=lambda p: proc_counts[p], reverse=True)[:40]
    active_sets = defaultdict(set)
    for proc in active_processes:
        for when in process_windows[proc]:
            active_sets[when].add(proc)
    cooccurrence = Counter()
    for active in active_sets.values():
        ordered = sorted(active)
        for i, first in enumerate(ordered):
            for second in ordered[i + 1:]:
                cooccurrence[(first, second)] += 1
    process_cooccurrence = []
    for (first, second), shared in cooccurrence.most_common(20):
        union = len(process_windows[first] | process_windows[second])
        process_cooccurrence.append({"first": first, "second": second, "shared_windows": shared,
                                     "jaccard": round(shared / union, 3) if union else 0})
    temporal_by_host = defaultdict(list)
    for record in temporal_records:
        temporal_by_host[record["host"]].append(record)
    host_epochs_by_host = {}
    for records in temporal_by_host.values():
        records.sort(key=lambda event: event["epoch"])
    for host, records in temporal_by_host.items():
        host_epochs_by_host[host] = [event["epoch"] for event in records]
    starts_by_host_process = defaultdict(list)
    start_events = []
    for records in temporal_by_host.values():
        for event in records:
            if event["process"] != "unknown" and PROCESS_START.search(event["message"]) and not START_FAILURE.search(event["message"]):
                event["is_start"] = True
                start_events.append(event)
                starts_by_host_process[(event["host"], event["process"])].append(event["epoch"])
    temporal_tree = []
    correlation_seconds = max(1, int(window_minutes)) * 60
    for start in sorted(start_events, key=lambda event: event["epoch"])[-100:]:
        host_records = temporal_by_host[start["host"]]
        host_epochs = host_epochs_by_host[start["host"]]
        left = bisect_left(host_epochs, start["epoch"])
        after = bisect_left(host_epochs, start["epoch"])
        same_proc_starts = starts_by_host_process[(start["host"], start["process"])]
        next_start_i = bisect_right(same_proc_starts, start["epoch"])
        stop_epoch = min(start["epoch"] + 1800, same_proc_starts[next_start_i] if next_start_i < len(same_proc_starts) else float("inf"))
        same_process_events = []
        for event in host_records[after:bisect_right(host_epochs, stop_epoch)]:
            if event is start:
                continue
            if start["host"] == "unknown" or event["epoch"] >= stop_epoch or (event.get("is_start") and event["process"] == start["process"]):
                break
            if event["process"] == start["process"]:
                same_process_events.append({key: event[key] for key in ("time", "process", "pid", "facility", "severity", "message")})
                if len(same_process_events) == 20:
                    break
        related_events = []
        for event in host_records[max(0, bisect_left(host_epochs, start["epoch"] - correlation_seconds)):bisect_right(host_epochs, start["epoch"] + correlation_seconds)]:
            if start["host"] == "unknown":
                break
            if event is start or event["process"] in ("unknown", start["process"]):
                continue
            related_events.append({"time": event["time"], "process": event["process"], "facility": event["facility"],
                                   "severity": event["severity"], "delta_seconds": round(event["epoch"] - start["epoch"]), "message": event["message"]})
        related_events.sort(key=lambda event: abs(event["delta_seconds"]))
        temporal_tree.append({"time": start["time"], "host": start["host"], "host_ip": start["host_ip"],
                              "process": start["process"], "pid": start["pid"], "facility": start["facility"],
                              "severity": start["severity"], "message": start["message"],
                              "process_events": same_process_events, "nearby_events": related_events[:10]})
    return {"total": len(rows), "process_count": len(proc_counts), "parsed": sum(1 for r in rows if r["process"] != "unknown"), "with_timestamp": sum(1 for r in rows if r["timestamp"]),
            "processes": [{"name": n, "count": c, "percent": round(c*100/len(rows),1) if rows else 0, "messages": [{"message": m, "count": k} for m,k in proc_messages[n].most_common(5)]} for n,c in proc_counts.most_common(30)],
            "severities": [{"name": n, "count": c} for n,c in severity_counts.most_common()], "hosts": [{"name": n, "count": c} for n,c in host_counts.most_common(10)],
            "host_ips": [{"name": n, "count": c} for n,c in host_ip_counts.most_common(10) if n != "unknown"],
            "facilities": [{"name": n, "count": c} for n,c in facility_counts.most_common(15) if n != "unknown"],
            "correlations": {"process_facility": top_associations(proc_facility), "process_severity": top_associations(proc_severity),
                             "process_host_ip": top_associations(proc_host_ip),
                             "process_cooccurrence": process_cooccurrence},
            "temporal_tree": temporal_tree,
            "messages": [{"message": n, "count": c} for n,c in msg_counts.most_common(15)], "series": {k:v for k,v in series.items() if k != "__all__"}, "spikes": spikes[:50], "window_minutes": window_minutes}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404); return
        body = (ROOT / "index.html").read_bytes()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if urlparse(self.path).path != "/api/analyze": self.send_error(404); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY: raise ValueError("File troppo grande: limite 30 MB")
            data = json.loads(self.rfile.read(length))
            result = analyze(str(data.get("content", "")), str(data.get("filename", "log.txt")), int(data.get("window", 5)), float(data.get("threshold", 2)))
            payload = json.dumps(result, ensure_ascii=False).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
        except Exception as exc:
            payload = json.dumps({"error": str(exc)}, ensure_ascii=False).encode(); self.send_response(400); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def log_message(self, *_): pass

if __name__ == "__main__":
    import argparse, webbrowser
    parser = argparse.ArgumentParser(description="Analizzatore locale di eventi Linux/syslog")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Syslog Analyser locale: http://127.0.0.1:{args.port} (Ctrl+C per terminare)")
    if not args.no_browser: webbrowser.open(f"http://127.0.0.1:{args.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nServer terminato.")
