import csv
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from analysis import analyze
from app import Handler
from parsing import normalize_row, parse_line, parse_timestamp, read_events

HEADER = ["TimeGenerated", "Computer", "Facility", "SecurityLevel", "SyslogMessage", "Processname", "HostIP"]
START = datetime(2026, 10, 5, 10, tzinfo=timezone.utc)


def row(minute, message="heartbeat", process="agent", host="pc-a", ip="10.0.0.1", level="info"):
    return [(START + timedelta(minutes=minute)).isoformat(), host, "daemon", level, message, process, ip]


def csv_text(rows, delimiter=",", bom=False):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=delimiter)
    writer.writerow(HEADER)
    writer.writerows(rows)
    return ("\ufeff" if bom else "") + output.getvalue()


def burst(message, number=30, process="agent", **kwargs):
    rows = [row(minute, process=process, **kwargs) for minute in (0, 5, 10)]
    rows += [row(15 + index / 100, message(index) if callable(message) else message, process=process, **kwargs)
             for index in range(number)]
    return rows


class ParserTests(unittest.TestCase):
    def test_exact_columns_bom_multiline_and_numeric_labels(self):
        content = csv_text([row(0, 'a, "quoted"\nsecond line', "worker[42]", level="4")], delimiter=";", bom=True)
        rows, quality = read_events(content, "test.csv")
        self.assertEqual(rows[0]["message"], 'a, "quoted"\nsecond line')
        self.assertEqual(rows[0]["process"], "worker")
        self.assertEqual(rows[0]["pid"], "42")
        self.assertEqual(rows[0]["severity"], "warning")
        self.assertEqual(rows[0]["host"], "pc-a")
        self.assertEqual(quality["mapping"]["timestamp"], "TimeGenerated")
        self.assertEqual(rows[0]["line"], 3)
        self.assertEqual(normalize_row({"Facility":"3"})["facility"], "daemon")

    def test_timestamps_offsets_and_ambiguous_order(self):
        self.assertEqual(parse_timestamp("2026-10-05T12:00:00+02:00")[0],
                         parse_timestamp("2026-10-05T10:00:00Z")[0])
        self.assertEqual(parse_timestamp("2026-10-05 12:00:00", "+02:00")[0], "2026-10-05T10:00:00Z")
        self.assertIn("assumed_timezone", parse_timestamp("2026-10-05 12:00:00")[1])
        self.assertEqual(parse_timestamp("05/10/2026 12:00:00", date_order="DMY")[0][:10], "2026-10-05")
        self.assertEqual(parse_timestamp("05/10/2026 12:00:00", date_order="MDY")[0][:10], "2026-05-10")
        self.assertTrue(parse_timestamp("2026-10-05T12:00:00.1234567Z")[0].endswith(".123456Z"))

    def test_invalid_dates_retained_and_reported(self):
        rows, quality = read_events(csv_text([["2026-02-31","pc","daemon","err","message","a","10.0.0.1"]]), "bad.csv")
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["timestamp"])
        self.assertEqual(quality["counts"]["invalid_timestamp"], 1)
        self.assertIsNone(parse_timestamp("Feb 31 12:00:00")[0])

    def test_syslog_pid_facility_structured_data(self):
        old = parse_line("<34>Oct  5 12:00:00 host sshd[42]: Failed password")
        self.assertEqual((old["process"], old["pid"], old["facility"]), ("sshd", "42", "auth"))
        new = parse_line('<30>1 2026-10-05T12:00:00Z host app 77 - [x a="b"][y n="z"] message')
        self.assertEqual((new["message"],new["pid"],new["facility"]), ("message","77","daemon"))

    def test_limits_and_malformed_csv_are_visible(self):
        rows, quality = read_events(csv_text([row(i) for i in range(4)]), "test.csv", limit=2)
        self.assertEqual(len(rows), 2)
        self.assertTrue(quality["truncated"])
        malformed = csv_text([row(0)]) + "bad,pc,daemon,info,message,agent,10.0.0.1,extra\n"
        self.assertEqual(read_events(malformed, "test.csv")[1]["counts"]["extra_csv_fields"], 1)


class AnalysisTests(unittest.TestCase):
    def test_window_percentages_evidence_and_retry_hypothesis(self):
        content = csv_text(burst("connection timed out; retrying", 24) + [row(16, "normal") for _ in range(6)])
        result = analyze(content, "retry.csv")
        incident = result["incidents"][0]
        self.assertEqual(result["spike_count"], 1)
        self.assertEqual(incident["count"], 30)
        suggestion = next(s for s in incident["suggestions"] if s["id"] == "retry_loop")
        self.assertEqual(suggestion["percent"], 80)
        self.assertEqual(suggestion["baseline_percent"], 0)
        self.assertEqual(suggestion["delta_pp"], 80)
        self.assertEqual(sum(c["count"] for c in incident["categories"]), 30)
        self.assertEqual(incident["baseline"], 1)
        self.assertTrue(all(e["row"] >= 4 for e in incident["evidence"]))
        self.assertNotIn("heartbeat", incident["messages"][0]["message"])
        self.assertIn("24/30", incident["ticket"])
        self.assertIn("SHA-256", incident["ticket"])
        self.assertEqual(len(result["source"]["sha256"]), 64)

    def test_host_isolation_and_process_spike_under_constant_host_load(self):
        rows = []
        for minute in (0, 5, 10, 15):
            rows += [row(minute, process="busy", host="pc-b", ip="10.0.0.2") for _ in range(30)]
            rows += [row(minute, process="stable") for _ in range(20 if minute != 15 else 2)]
            rows += [row(minute, "connection reset", process="new") for _ in range(1 if minute != 15 else 19)]
        result = analyze(csv_text(rows), "host.csv")
        spike = next(i for i in result["incidents"] if i["host"] == "pc-a")
        self.assertEqual(spike["kind"], "spike processo")
        self.assertEqual(spike["count"], 21)
        self.assertFalse(spike["detected"])
        self.assertTrue(next(p for p in spike["processes"] if p["name"] == "new")["detected"])
        self.assertFalse(next(i for i in result["incidents"] if i["host"] == "pc-b")["detected"])

    def test_early_large_window_is_not_a_proven_spike(self):
        result = analyze(csv_text([row(0,"connection reset") for _ in range(100)]), "one.csv")
        self.assertEqual(result["spike_count"], 0)
        self.assertEqual(result["incidents"][0]["baseline_windows"], 0)
        self.assertIn("non dimostrato",result["incidents"][0]["kind"])

    def test_auth_gates_and_matching_success_sequence(self):
        rows = burst(lambda n: "Failed password for root from 192.0.2.9 port 45678", 15, process="sshd")
        rows += [row(16, "Accepted password for root from 192.0.2.9 port 45678", "sshd")]
        incident = analyze(csv_text(rows), "auth.csv")["incidents"][0]
        brute = next(s for s in incident["suggestions"] if s["id"]=="brute_force")
        self.assertEqual(brute["mitre_refs"][0]["id"],"T1110")
        self.assertEqual(incident["sequences"][0]["failures"], 15)
        no_peer = analyze(csv_text(burst("authentication failure",20,"sshd")), "auth.csv")["incidents"][0]
        self.assertNotIn("brute_force", [s["id"] for s in no_peer["suggestions"]])
        wrong_user = analyze(csv_text(rows[:-1] + [row(16,"Accepted password for other from 192.0.2.9 port 1","sshd")]), "a.csv")
        self.assertEqual(wrong_user["incidents"][0]["sequences"], [])

    def test_dns_errors_do_not_imply_dns_tunnel(self):
        incident = analyze(csv_text(burst("DNS resolver SERVFAIL", 30)), "dns.csv")["incidents"][0]
        self.assertIn("dns_resolution",[s["id"] for s in incident["suggestions"]])
        self.assertFalse(any(s["mitre_refs"] for s in incident["suggestions"]))
        tunnel = analyze(csv_text(burst("DNS tunneling detected", 30)), "dns.csv")["incidents"][0]
        self.assertIn("dns_tunnel", [s["id"] for s in tunnel["suggestions"]])

    def test_negative_security_messages_do_not_trigger_mitre(self):
        for message in ("DNS tunneling not detected", "No DNS tunneling detected",
                        "DNS tunneling disabled", "file access denied", "created socket"):
            incident = analyze(csv_text(burst(message, 20)), "negative.csv")["incidents"][0]
            self.assertFalse(any(s["mitre_refs"] for s in incident["suggestions"]), message)

    def test_duplicate_export_record_kept_and_flagged(self):
        result = analyze(csv_text([row(0),row(0)]), "duplicate.csv")
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["quality"]["counts"]["identical_records"], 1)

    def test_updates_are_operational_and_no_mitre_by_volume_alone(self):
        incident = analyze(csv_text(burst("apt downloading package updates", 30,"apt")), "update.csv")["incidents"][0]
        self.assertIn("updates",[s["id"] for s in incident["suggestions"]])
        self.assertFalse(any(s["mitre_refs"] for s in incident["suggestions"]))

    def test_outbound_scan_requires_explicit_local_source(self):
        outgoing = burst(lambda n: f"SRC=10.0.0.1 DST=192.0.2.{n+1} SPT=45000 DPT=443", 20, "kernel")
        incident = analyze(csv_text(outgoing), "scan.csv")["incidents"][0]
        self.assertIn("scan", [s["id"] for s in incident["suggestions"]])
        inbound = burst(lambda n: f"SRC=192.0.2.{n+1} DST=10.0.0.1 SPT=45000 DPT=443", 20, "kernel")
        incident = analyze(csv_text(inbound), "scan.csv")["incidents"][0]
        self.assertNotIn("scan", [s["id"] for s in incident["suggestions"]])
        self.assertEqual(incident["network"]["directions"][0]["name"],"inbound")

    def test_timezone_normalized_into_same_bucket(self):
        rows = [row(0),row(0)]
        rows[1][0] = "2026-10-05T12:00:00+02:00"
        result = analyze(csv_text(rows), "offset.csv")
        self.assertEqual(len(result["chart"]),1)
        self.assertEqual(result["chart"][0]["count"],2)

    def test_tree_does_not_claim_socket_creation_is_process_start(self):
        result = analyze(csv_text([row(0,"created socket"), row(1,"heartbeat"),
                                   row(1,"other machine","agent","pc-b","10.0.0.2")]), "tree.csv")
        root = next(s for s in result["temporal_tree"] if s["host"]=="pc-a")
        self.assertIn("non dimostrato", root["status"])
        self.assertTrue(all(e["host"]=="pc-a" for e in root["process_events"]+root["nearby_events"]))

    def test_tree_reports_systemd_as_observer(self):
        result=analyze(csv_text([row(0,"Started example.service.","systemd[1]"),row(1,"request","example.service[42]")]),"tree.csv")
        root=next(s for s in result["temporal_tree"] if s["status"]=="avvio segnalato")
        self.assertEqual(root["process"],"systemd")
        self.assertEqual(root["pid"],"1")
        self.assertEqual(root["target_pid"],"")
        self.assertEqual(root["target"],"example.service")
        self.assertEqual(root["process_events"][0]["process"],"example.service")
        self.assertEqual(root["process_events"][0]["pid"],"42")

    def test_empty_missing_identity_sparse_dates_and_nonfinite_inputs(self):
        self.assertEqual(analyze("", "empty.log")["total"],0)
        result=analyze(csv_text([row(0, host="",ip="")]),"unknown.csv")
        self.assertEqual(result["incidents"],[])
        self.assertEqual(result["temporal_tree"],[])
        rows=[row(0),row(0)]
        rows[1][0]="2036-10-05T10:00:00Z"
        result=analyze(csv_text(rows),"sparse.csv")
        self.assertLessEqual(len(result["chart"]),600)
        self.assertEqual(sum(p["count"] for p in result["chart"]),2)
        for options in ({"threshold":float("nan")},{"window_minutes":0},{"min_events":2},{"window_minutes":1.5}):
            with self.assertRaises(ValueError):
                analyze("","empty.csv",**options)

    def test_cooccurrence_requires_same_host(self):
        rows=[row(t,process="a") for t in (0,5,10)] + [row(t,process="b",host="pc-b",ip="10.0.0.2") for t in (0,5,10)]
        self.assertEqual(analyze(csv_text(rows),"hosts.csv")["correlations"]["process_cooccurrence"],[])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1",0),Handler)
        cls.thread=Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_assets_and_analysis_http(self):
        for path in ("/","/app.js","/styles.css"):
            with urlopen(self.base+path) as response:
                self.assertEqual(response.status,200)
                self.assertIn("connect-src 'self'",response.headers["Content-Security-Policy"])
        body=json.dumps({"filename":"sample.csv","content":csv_text(burst("connection reset",20))}).encode()
        request=Request(self.base+"/api/analyze",body,{"Content-Type":"application/json"})
        with urlopen(request) as response:
            self.assertEqual(json.load(response)["spike_count"],1)

    def test_foreign_origin_and_bad_parameters_rejected(self):
        for headers,body,status in [
            ({"Content-Type":"application/json","Origin":"https://example.com"},{},403),
            ({"Content-Type":"application/json"},{"window":0},400),
            ({"Content-Type":"application/json"},[],400)]:
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(self.base+"/api/analyze",json.dumps(body).encode(),headers))
            self.assertEqual(error.exception.code,status)


if __name__ == "__main__":
    unittest.main()
