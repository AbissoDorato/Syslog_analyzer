#!/usr/bin/env python3
"""Local syslog ticket assistant. Python standard library only."""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from analysis import analyze
from parsing import MAX_EVENTS, MAX_FILE, normalize_row, parse_line, timestamp
from import_diagnostics import ImportFailure

ROOT = Path(__file__).resolve().parent
ASSETS = {"/": ("index.html", "text/html"), "/index.html": ("index.html", "text/html"),
          "/app.js": ("app.js", "text/javascript"), "/styles.css": ("styles.css", "text/css")}


class Handler(BaseHTTPRequestHandler):
    def import_limits(self):
        return {"max_file_bytes": getattr(self.server, "max_file_bytes", MAX_FILE),
                "max_events": getattr(self.server, "max_events", MAX_EVENTS)}

    def respond(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def error_json(self, status, message):
        self.respond(status, json.dumps({"error": message}, ensure_ascii=False).encode("utf-8"))

    def local_request(self):
        port = self.server.server_port
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host") in allowed_hosts and (
            not origin or origin in {f"http://{host}" for host in allowed_hosts})

    def do_GET(self):
        if not self.local_request():
            self.error_json(403, "Accesso consentito solo dall'app locale.")
            return
        path = urlparse(self.path).path
        if path == "/config.js":
            self.respond(200, ("globalThis.SYSLOG_CONFIG = " + json.dumps(self.import_limits()) + ";\n").encode("utf-8"),
                         "text/javascript")
            return
        asset = ASSETS.get(path)
        if not asset:
            self.error_json(404, "Risorsa non trovata.")
            return
        self.respond(200, (ROOT / asset[0]).read_bytes(), asset[1])

    def do_POST(self):
        if not self.local_request():
            self.error_json(403, "Origine non consentita.")
            return
        if urlparse(self.path).path != "/api/analyze":
            self.error_json(404, "API non trovata.")
            return
        try:
            self.connection.settimeout(300)
            if self.headers.get_content_type() != "application/json":
                raise ValueError("Content-Type richiesto: application/json.")
            length = int(self.headers.get("Content-Length", "0"))
            limits = self.import_limits()
            # JSON escaping can expand the UTF-8 content up to six times.
            max_body = limits["max_file_bytes"] * 6 + 4096
            if not 0 < length <= max_body:
                self.error_json(413, "Richiesta troppo grande o vuota. Limite contenuto: "
                                f"{limits['max_file_bytes'] // (1024 * 1024)} MB; "
                                "aumenta --max-file-mb all'avvio o suddividi il file.")
                self.close_connection = True
                return
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Il corpo deve essere un oggetto JSON.")
            result = analyze(data.get("content", ""), data.get("filename", "log.txt"),
                             window_minutes=float(data.get("window", 5)),
                             threshold=2.0 if data.get("use_history") is False else float(data.get("threshold", 2)),
                             min_events=float(data.get("min_events", 5)),
                             naive_offset=data.get("naive_offset", "+00:00"),
                             date_order=data.get("date_order", "DMY"),
                             use_history=data.get("use_history", True),
                             delimiter=data.get("delimiter", "auto"),
                             max_file_bytes=limits["max_file_bytes"], max_events=limits["max_events"])
            self.respond(200, json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        except ImportFailure as exc:
            self.respond(422, json.dumps({"error": str(exc), "error_type": "import", "quality": exc.report},
                                        ensure_ascii=False).encode("utf-8"))
        except (ValueError, TypeError, OverflowError) as exc:
            self.error_json(400, str(exc))
        except (TimeoutError, ConnectionError):
            self.close_connection = True
        except MemoryError:
            self.error_json(503, "Memoria disponibile insufficiente per questa analisi. "
                            "Riduci --max-events o suddividi il file per host o intervallo temporale.")
        except Exception:
            self.error_json(500, "Errore interno dell'analizzatore; questo non dimostra un problema nel file.")

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description="Analisi syslog e bozze di ticket, interamente locale")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--max-file-mb", type=int, default=MAX_FILE // (1024 * 1024),
                        help="Dimensione massima del file e del contenuto UTF-8 in MB (predefinito: 200)")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS,
                        help="Numero massimo di record esaminati per import (predefinito: 250000)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port deve essere compresa tra 1 e 65535.")
    if args.max_file_mb < 1 or args.max_events < 1:
        parser.error("--max-file-mb e --max-events devono essere interi positivi.")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"Avvio non riuscito sulla porta {args.port}: {exc}. Provare --port 9000.", file=sys.stderr)
        return 1
    server.max_file_bytes = args.max_file_mb * 1024 * 1024
    server.max_events = args.max_events
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"Syslog Analyser: {url} (Ctrl+C per terminare)")
    print(f"Limiti import: {args.max_file_mb} MB; {args.max_events} record per file.")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except webbrowser.Error:
            print(f"Aprire il browser su {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer terminato.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
