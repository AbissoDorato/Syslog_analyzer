#!/usr/bin/env python3
"""Offline Linux/syslog event analyser. Uses only the Python standard library."""
from __future__ import annotations

import csv
import io
import json
import re
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
    clean = {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}
    def pick(*keys):
        return next((clean[k] for k in keys if clean.get(k)), "")
    raw = pick("message", "msg", "event", "log", "content", "description", "testo")
    ts = pick("timestamp", "time", "datetime", "date", "@timestamp", "data", "ora")
    host = pick("hostname", "host", "computer", "machine")
    proc = pick("process", "process_name", "program", "application", "app", "comm", "unit", "service")
    pid = pick("pid", "process_id")
    severity = pick("severity", "level", "priority", "loglevel")
    if raw:
        parsed = parse_line(raw)
        return {**parsed, "timestamp": timestamp(ts) or parsed["timestamp"], "host": host or parsed["host"],
                "process": proc or parsed["process"], "pid": pid or parsed["pid"], "severity": severity or parsed["severity"], "raw": raw}
    return {"timestamp": timestamp(ts), "host": host or "unknown", "process": proc or "unknown", "pid": pid,
            "severity": severity or "unknown", "message": raw or " ".join(f"{k}={v}" for k, v in clean.items() if v), "raw": json.dumps(clean, ensure_ascii=False)}

def parse_line(line: str) -> dict:
    raw = line.strip()
    out = {"timestamp": None, "host": "unknown", "process": "unknown", "pid": "", "severity": "unknown", "message": raw, "raw": raw}
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
    proc_counts, severity_counts, host_counts, msg_counts = Counter(), Counter(), Counter(), Counter()
    proc_messages = defaultdict(Counter)
    timed = defaultdict(Counter)
    for r in rows:
        proc_counts[r["process"]] += 1; severity_counts[r["severity"]] += 1; host_counts[r["host"]] += 1
        msg = re.sub(r"\b\d+\b", "<n>", r["message"].lower())
        msg = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", msg)
        msg = re.sub(r"\s+", " ", msg).strip()[:180] or "(messaggio vuoto)"
        msg_counts[msg] += 1; proc_messages[r["process"]][msg] += 1
        if r["timestamp"]:
            try:
                dt = datetime.fromisoformat(r["timestamp"])
                window_seconds = max(1, window_minutes) * 60
                bucket_epoch = int(dt.timestamp()) // window_seconds * window_seconds
                minute = datetime.fromtimestamp(bucket_epoch, tz=dt.tzinfo)
                timed[(r["process"], minute.isoformat())]["count"] += 1
                timed[("__all__", minute.isoformat())]["count"] += 1
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
    return {"total": len(rows), "process_count": len(proc_counts), "parsed": sum(1 for r in rows if r["process"] != "unknown"), "with_timestamp": sum(1 for r in rows if r["timestamp"]),
            "processes": [{"name": n, "count": c, "percent": round(c*100/len(rows),1) if rows else 0, "messages": [{"message": m, "count": k} for m,k in proc_messages[n].most_common(5)]} for n,c in proc_counts.most_common(30)],
            "severities": [{"name": n, "count": c} for n,c in severity_counts.most_common()], "hosts": [{"name": n, "count": c} for n,c in host_counts.most_common(10)],
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
