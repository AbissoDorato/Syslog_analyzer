"""CSV/syslog parsing. No network access; timestamps are normalized to UTC."""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from itertools import islice

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
        event["timestamp"], event["flags"] = parse_timestamp(fields["ts"], offset, date_order)
        if fields.get("pri") and 0 <= int(fields["pri"]) <= 191:
            pri = int(fields["pri"])
            event["severity"], event["facility"] = SEVERITIES[pri % 8], FACILITIES[pri // 8]
    return event


def normalize_row(row, offset="+00:00", date_order="DMY"):
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
    event["columns"] = {field: fields[field] for field in fields}
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


def read_events(content, filename, offset="+00:00", date_order="DMY", limit=MAX_EVENTS):
    offset_timezone(offset)
    if date_order not in ("DMY", "MDY"):
        raise ValueError("Ordine delle date non valido.")
    if len(content.encode("utf-8")) > MAX_FILE:
        raise ValueError("File troppo grande: limite 30 MB in UTF-8.")
    quality = Counter()
    columns = []
    mapping = {}
    if filename.lower().endswith(".csv"):
        # Prefer the delimiter yielding recognized columns: message text can contain commas.
        first = content.lstrip("\ufeff").split("\n", 1)[0]
        known = {alias for aliases in ALIASES.values() for alias in aliases}
        delimiter = max(",;\t|", key=lambda sep: sum(header(x) in known for x in next(
            csv.reader([first], delimiter=sep), [])))
        csv.field_size_limit(MAX_FILE)
        reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff"), newline=""), delimiter=delimiter)
        columns = reader.fieldnames or []
        mapping = {field: next((column for column in columns if header(column) in aliases), None)
                   for field, aliases in ALIASES.items()}
        def csv_events():
            try:
                for number, row in enumerate(reader, 1):
                    event = normalize_row(row, offset, date_order)
                    event["row"] = number
                    event["line"] = reader.line_num
                    yield event
            except csv.Error as exc:
                raise ValueError(f"CSV non valido vicino alla riga {reader.line_num}: {exc}") from exc
        source = csv_events()
    else:
        def text_events():
            for number, line in enumerate(io.StringIO(content), 1):
                if line.strip():
                    event = parse_line(line, offset, date_order)
                    event.update(row=number, line=number)
                    yield event
        source = text_events()
    rows = list(islice(source, limit + 1))
    truncated = len(rows) > limit
    rows = rows[:limit]
    seen = set()
    for row in rows:
        signature = hashlib.blake2b(repr(tuple(row[key] for key in (
            "timestamp", "host", "host_ip", "process", "pid", "facility", "severity", "raw"))).encode("utf-8"), digest_size=16).digest()
        if signature in seen:
            quality["identical_records"] += 1
        seen.add(signature)
        quality.update(row["flags"])
        if row["host"] == UNKNOWN:
            quality["missing_host"] += 1
        if row["process"] == UNKNOWN:
            quality["missing_process"] += 1
        row["epoch"] = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp() if row["timestamp"] else None
        # Missing identities are kept separate; do not correlate unrelated unknown hosts.
        row["host_key"] = row["host"] if row["host"] != UNKNOWN else (
            row["host_ip"] if clean_ip(row["host_ip"]) else f"unknown-row-{row['row']}")
    return rows, {"counts": dict(quality), "columns": columns, "mapping": mapping,
                  "truncated": truncated, "event_limit": limit, "naive_offset": offset,
                  "date_order": date_order}
