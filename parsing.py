"""CSV/syslog parsing. No network access; timestamps are normalized to UTC."""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from import_diagnostics import Diagnostics, FIELD_NAMES, ImportFailure

MAX_EVENTS = 250_000
MAX_FILE = 30 * 1024 * 1024
UNKNOWN = "unknown"
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
              "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
              "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7")
MONTHS = {name: i for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
ALIASES = {
    "timestamp": ("timegenerated", "timestamp", "time", "datetime", "date", "@timestamp", "data", "ora"),
    "host": ("computer", "hostname", "host", "machine"),
    "facility": ("facility", "syslogfacility"),
    "severity": ("securitylevel", "severity", "level", "priority", "loglevel"),
    "message": ("syslogmessage", "message", "msg", "event", "log", "content", "description", "testo"),
    "process": ("processname", "process", "program", "application", "app", "comm", "unit", "service"),
    "pid": ("pid", "processid"),
    "host_ip": ("hostip", "ip", "ipaddress"),
}
TAG = re.compile(r"^(?P<proc>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?$")
RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$", re.S)
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
    r"\s+(?P<host>\S+)\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$", re.S)
RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>\d+ (?P<ts>\S+) (?P<host>\S+) (?P<proc>\S+) (?P<pid>\S+) \S+ "
    r"(?P<tail>.*)$", re.S)


def header(value):
    return re.sub(r"[\s_\-]", "", str(value or "").lstrip("\ufeff")).lower()


def value_or_empty(value):
    value = str(value or "").strip()
    return "" if value.lower() in ("-", "null", "n/a", "none", "unknown") else value


def offset_timezone(offset):
    if not re.fullmatch(r"[+-]\d{2}:\d{2}", offset):
        raise ValueError("Il fuso deve avere formato +HH:MM o -HH:MM.")
    hours, minutes = map(int, offset[1:].split(":"))
    if minutes > 59 or hours > 14 or (hours == 14 and minutes):
        raise ValueError("Fuso orario fuori intervallo (massimo ±14:00).")
    return timezone(timedelta(minutes=(hours * 60 + minutes) * (-1 if offset[0] == "-" else 1)))


def parse_timestamp(value, offset="+00:00", date_order="DMY"):
    """Return canonical time and quality flags; never guess ambiguous day/month order."""
    value = value_or_empty(value)
    flags = []
    if not value:
        return None, ["missing_timestamp"]
    try:
        text = value.replace(" UTC", "+00:00").replace("Z", "+00:00")
        # Python 3.10 accepts six fractional digits reliably.
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            match = re.fullmatch(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)", value)
            if match and match[1] in MONTHS:
                dt = datetime(datetime.now(timezone.utc).year, MONTHS[match[1]], int(match[2]),
                              *map(int, match[3].split(":")))
                flags.append("inferred_year")
            else:
                fmt = "%d/%m/%Y" if date_order == "DMY" else "%m/%d/%Y"
                dt = None
                for suffix in (" %H:%M:%S.%f", " %H:%M:%S", " %H:%M", " %I:%M:%S %p"):
                    try:
                        dt = datetime.strptime(value, fmt + suffix)
                        break
                    except ValueError:
                        continue
                if dt is None:
                    raise ValueError("invalid date")
                parts = value.split(" ", 1)[0].split("/")
                if len(parts) == 3 and 1 <= int(parts[0]) <= 12 and 1 <= int(parts[1]) <= 12 and int(parts[0]) != int(parts[1]):
                    flags.append("ambiguous_date")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=offset_timezone(offset))
            flags.append("assumed_timezone")
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), flags
    except (ValueError, OverflowError):
        return None, ["invalid_timestamp"]


def timestamp(value):
    return parse_timestamp(value)[0]


def normalize_severity(value):
    value = value_or_empty(value).lower()
    if value.isdigit() and 0 <= int(value) < 8:
        return SEVERITIES[int(value)]
    return {"emerg": "emergency", "panic": "emergency", "crit": "critical", "err": "error",
            "warn": "warning", "informational": "info", "information": "info"}.get(value, value or UNKNOWN)


def normalize_facility(value):
    value = value_or_empty(value).lower()
    if value.isdigit() and 0 <= int(value) < len(FACILITIES):
        return FACILITIES[int(value)]
    return value or UNKNOWN


def clean_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip("[]")))
    except ValueError:
        return ""


def split_tag(tag):
    match = TAG.fullmatch(tag.strip())
    return (match["proc"], match["pid"] or "") if match else (tag.strip() or UNKNOWN, "")


def strip_structured_data(tail):
    if tail.startswith("- "):
        return tail[2:]
    if tail == "-":
        return ""
    pos = 0
    while pos < len(tail) and tail[pos] == "[":
        pos += 1
        while pos < len(tail):
            if tail[pos] == "\\":
                pos += 2
                continue
            if tail[pos] == "]":
                pos += 1
                break
            pos += 1
    return tail[pos:].lstrip() if pos else tail


def parse_line(line, offset="+00:00", date_order="DMY"):
    raw = line.strip()
    event = dict(timestamp=None, host=UNKNOWN, process=UNKNOWN, pid="", severity=UNKNOWN,
                 facility=UNKNOWN, host_ip=UNKNOWN, message=raw, raw=raw, flags=["missing_timestamp"])
    match = RFC5424.match(raw)
    if match:
        fields = match.groupdict()
        event.update(host=value_or_empty(fields["host"]) or UNKNOWN,
                     process=value_or_empty(fields["proc"]) or UNKNOWN,
                     pid=value_or_empty(fields["pid"]), message=strip_structured_data(fields["tail"]))
    else:
        match = RFC3164.match(raw) or ISO_LINE.match(raw)
        if match:
            fields = match.groupdict()
            proc, pid = split_tag(fields["tag"])
            event.update(host=fields["host"], process=proc, pid=pid, message=fields["msg"])
        else:
            tag_match = re.match(r"^([\w./@-]+(?:\[\d+\])?):\s*(.*)$", raw, re.S)
            if tag_match:
                event["process"], event["pid"] = split_tag(tag_match[1])
                event["message"] = tag_match[2]
    if match:
        event["input_timestamp"] = fields["ts"]
        event["timestamp"], event["flags"] = parse_timestamp(fields["ts"], offset, date_order)
        if fields.get("pri") and 0 <= int(fields["pri"]) <= 191:
            pri = int(fields["pri"])
            event["severity"], event["facility"] = SEVERITIES[pri % 8], FACILITIES[pri // 8]
    return event


def normalize_row(row, offset="+00:00", date_order="DMY"):
    originals = {header(k): str(v if v is not None else "") for k, v in row.items() if k is not None}
    clean = {header(k): value_or_empty(v) for k, v in row.items() if k is not None}
    fields = {field: next((clean[key] for key in keys if clean.get(key)), "")
              for field, keys in ALIASES.items()}
    event = parse_line(fields["message"], offset, date_order)
    if fields["timestamp"]:
        event["timestamp"], event["flags"] = parse_timestamp(fields["timestamp"], offset, date_order)
    for field in ("host", "host_ip", "pid"):
        if fields[field]:
            event[field] = fields[field]
    if fields["process"]:
        event["process"], tag_pid = split_tag(fields["process"])
        event["pid"] = fields["pid"] or tag_pid or event["pid"]
    if fields["severity"]:
        event["severity"] = normalize_severity(fields["severity"])
    if fields["facility"]:
        event["facility"] = normalize_facility(fields["facility"])
    if event["severity"] not in (*SEVERITIES, UNKNOWN):
        event["flags"].append("unrecognized_severity")
    if event["facility"] not in (*FACILITIES, UNKNOWN):
        event["flags"].append("unrecognized_facility")
    event["columns"] = {
        field: next((originals[key] for key in keys if clean.get(key)),
                    next((originals[key] for key in keys if key in originals), ""))
        for field, keys in ALIASES.items()}
    if not fields["message"]:
        event["flags"].append("missing_message")
    if row.get(None):
        event["flags"].append("extra_csv_fields")
    if any(value is None for key, value in row.items() if key is not None):
        event["flags"].append("missing_csv_fields")
    if event["host_ip"] != UNKNOWN and not clean_ip(event["host_ip"]):
        event["flags"].append("invalid_host_ip")
    elif event["host_ip"] != UNKNOWN:
        event["host_ip"] = clean_ip(event["host_ip"])
    return event


def read_events(content, filename, offset="+00:00", date_order="DMY", limit=MAX_EVENTS, delimiter="auto"):
    offset_timezone(offset)
    if date_order not in ("DMY", "MDY"):
        raise ValueError("Ordine delle date non valido.")
    if delimiter not in ("auto", ",", ";", "\t", "|"):
        raise ValueError("Separatore non valido: scegli automatico, virgola, punto e virgola, tab o pipe.")
    diag = Diagnostics()
    rows, records_read, skipped = [], 0, 0
    base = {"columns": [], "mapping": {}, "truncated": False, "event_limit": limit,
            "naive_offset": offset, "date_order": date_order,
            "format": {"type": "csv" if filename.lower().endswith(".csv") else "syslog",
                       "delimiter": None, "delimiter_mode": delimiter}}
    def blocked(code, value="", **location):
        diag.add(code, value=value, **location)
        raise ImportFailure(diag.items[code]["title"],
                            diag.report(base, rows, records_read, skipped, blocked=True, complete=False))
    if len(content.encode("utf-8")) > MAX_FILE:
        blocked("file_too_large", f"{len(content.encode('utf-8'))} byte UTF-8")
    if "\0" in content:
        blocked("null_bytes", "Caratteri NUL nel contenuto")
    if filename.lower().endswith(".csv"):
        text = content.lstrip("\ufeff")
        first = next((line for line in io.StringIO(text) if line.strip()), "")
        known = {alias for aliases in ALIASES.values() for alias in aliases}
        if delimiter == "auto":
            delimiter = max(",;\t|", key=lambda sep: sum(header(x) in known for x in next(
                csv.reader([first], delimiter=sep), [])))
        base["format"]["delimiter"] = delimiter
        csv.field_size_limit(MAX_FILE)
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        columns = []
        try:
            for values in reader:
                if values:
                    columns = values
                    break
        except csv.Error as exc:
            blocked("csv_syntax", str(exc), line_start=1, line_end=reader.line_num)
        base["columns"] = columns
        normalized = [header(column) for column in columns]
        if columns:
            duplicates = [name for name, count in Counter(normalized).items() if count > 1]
            if duplicates:
                blocked("duplicate_headers", ", ".join(duplicates), line_start=1, line_end=reader.line_num)
            if any(not name for name in normalized):
                blocked("empty_header", "Colonna senza nome", line_start=1, line_end=reader.line_num)
            for field, aliases in ALIASES.items():
                matches = [column for alias in aliases for column in columns if header(column) == alias]
                base["mapping"][field] = matches[0] if matches else None
                if len(matches) > 1:
                    diag.add("ambiguous_alias", column=FIELD_NAMES[field], value=" → ".join(matches),
                             line_start=1, line_end=reader.line_num)
            if not any(base["mapping"].values()):
                blocked("unrecognized_columns", " | ".join(column[:60] for column in columns[:8]),
                        line_start=1, line_end=reader.line_num)
            for field, column in base["mapping"].items():
                if column is None and field != "pid":
                    diag.add("missing_column", column=FIELD_NAMES[field], value="Colonna assente",
                             line_start=1, line_end=reader.line_num)
        while columns:
            line_start = reader.line_num + 1
            try:
                values = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                if records_read >= limit:
                    base["truncated"] = True
                    diag.add("event_limit", value=f"Limite: {limit} record")
                    break
                blocked("csv_syntax", str(exc), record=records_read + 1,
                        line_start=line_start, line_end=reader.line_num)
            if not values:
                continue
            if records_read >= limit:
                base["truncated"] = True
                diag.add("event_limit", value=f"Limite: {limit} record")
                break
            records_read += 1
            if len(values) != len(columns):
                code = "extra_csv_fields" if len(values) > len(columns) else "missing_csv_fields"
                diag.add(code, record=records_read, line_start=line_start, line_end=reader.line_num,
                         value=f"Attese {len(columns)} colonne; trovate {len(values)}. " +
                               " | ".join(value[:40] for value in values[:4]))
                skipped += 1
                continue
            event = normalize_row(dict(zip(columns, values)), offset, date_order)
            event.update(row=records_read, line_start=line_start, line=reader.line_num)
            rows.append(event)
    else:
        for number, line in enumerate(io.StringIO(content), 1):
            if not line.strip():
                continue
            if records_read >= limit:
                base["truncated"] = True
                diag.add("event_limit", value=f"Limite: {limit} record")
                break
            records_read += 1
            event = parse_line(line, offset, date_order)
            event.update(row=number, line_start=number, line=number)
            rows.append(event)
    seen = set()
    for row in rows:
        signature = hashlib.blake2b(repr(tuple(row[key] for key in (
            "timestamp", "host", "host_ip", "process", "pid", "facility", "severity", "raw"))).encode("utf-8"), digest_size=16).digest()
        if signature in seen:
            row["flags"].append("identical_records")
        seen.add(signature)
        if row["host"] == UNKNOWN:
            row["flags"].append("missing_host")
        if row["process"] == UNKNOWN:
            row["flags"].append("missing_process")
        for flag in row["flags"]:
            field = {"invalid_host_ip": "host_ip", "unrecognized_severity": "severity",
                     "unrecognized_facility": "facility"}.get(flag, flag.removeprefix("missing_"))
            if flag in ("invalid_timestamp", "assumed_timezone", "ambiguous_date", "inferred_year"):
                field = "timestamp"
            diag.add(flag, event=row, column=base["mapping"].get(field))
        row["epoch"] = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp() if row["timestamp"] else None
        # Missing identities are kept separate; do not correlate unrelated unknown hosts.
        row["host_key"] = row["host"] if row["host"] != UNKNOWN else (
            row["host_ip"] if clean_ip(row["host_ip"]) else f"unknown-row-{row['row']}")
    if not records_read:
        diag.add("no_records", value="File vuoto o senza record dopo l'intestazione")
    if not rows and skipped:
        raise ImportFailure("Nessun record CSV con struttura valida.",
                            diag.report(base, rows, records_read, skipped, blocked=True, complete=not base["truncated"]))
    return rows, diag.report(base, rows, records_read, skipped, complete=not base["truncated"])
