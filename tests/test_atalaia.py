import os
import tempfile
import unittest

from atalaia.ai import sanitize
from atalaia.collectors import FileTailer, FimScanner
from atalaia.engine import Engine, load_rules
from atalaia.parsers import parse_line
from atalaia.storage import Store

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def run_file(engine, stype, path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            ev = parse_line(stype, line)
            if ev:
                engine.process(ev)


class ParserTest(unittest.TestCase):
    def test_ssh_fail(self):
        ev = parse_line("auth", "Sep 24 03:12:12 vps sshd[1]: Failed password for root from 203.0.113.4 port 5 ssh2")
        self.assertEqual(ev["etype"], "ssh_fail")
        self.assertEqual(ev["ip"], "203.0.113.4")
        self.assertEqual(ev["user"], "root")

    def test_iso_timestamp(self):
        ev = parse_line("auth", "2026-09-24T03:12:12.123456-03:00 vps sshd[1]: Accepted publickey for ana from 198.51.100.9 port 1 ssh2")
        self.assertEqual(ev["etype"], "ssh_success")
        self.assertEqual(ev["user"], "ana")

    def test_http_combined_decodes_path(self):
        line = '198.51.100.11 - - [24/Sep/2026:10:00:00 -0300] "GET /a?id=1%27%20OR%201=1 HTTP/1.1" 200 10 "-" "curl"'
        ev = parse_line("http", line)
        self.assertIn("' OR 1=1", ev["path"])
        self.assertEqual(ev["status"], "200")

    def test_traefik_json(self):
        line = '{"ClientHost":"198.51.100.22","RequestMethod":"GET","RequestPath":"/.env","DownstreamStatus":404}'
        ev = parse_line("http", line)
        self.assertEqual(ev["ip"], "198.51.100.22")
        self.assertEqual(ev["status"], "404")

    def test_firewall(self):
        line = "Sep 24 11:00:00 vps kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.8 DST=10.0.0.1 LEN=40 PROTO=TCP SPT=1 DPT=3306"
        ev = parse_line("firewall", line)
        self.assertEqual(ev["dpt"], "3306")

    def test_garbage_ignored(self):
        self.assertIsNone(parse_line("auth", "linha qualquer sem relevancia"))
        self.assertIsNone(parse_line("http", "lixo"))


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.engine = Engine(load_rules(), self.store, skip_kinds={"new_value"})

    def rules_fired(self):
        return {a["rule_id"] for a in self.store.alerts_since(0)}

    def test_attack_chain_detected(self):
        run_file(self.engine, "auth", os.path.join(SAMPLES, "auth.log"))
        fired = self.rules_fired()
        for rule in ("SSH-001", "SSH-002", "SSH-004", "SYS-001", "SYS-002", "SYS-003"):
            self.assertIn(rule, fired)

    def test_web_attacks_detected(self):
        run_file(self.engine, "http", os.path.join(SAMPLES, "access.log"))
        fired = self.rules_fired()
        for rule in ("WEB-002", "WEB-003", "WEB-004", "WEB-005", "WEB-007"):
            self.assertIn(rule, fired)

    def test_normal_traffic_is_normal(self):
        line = '192.0.2.101 - - [24/Sep/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
        ev = parse_line("http", line)
        self.assertEqual(self.engine.process(ev), [])
        self.assertEqual(ev["classificacao"], "normal")

    def test_whitelist(self):
        engine = Engine(load_rules(), self.store, whitelist=["203.0.113.0/24"])
        run_file(engine, "auth", os.path.join(SAMPLES, "auth.log"))
        ips = {a["ip"] for a in self.store.alerts_since(0)}
        self.assertNotIn("203.0.113.10", ips)

    def test_cooldown_groups_repeated_alerts(self):
        for _ in range(5):
            ev = parse_line("http", '198.51.100.9 - - [24/Sep/2026:10:00:00 -0300] "GET /.git/config HTTP/1.1" 404 1 "-" "x"')
            self.engine.process(ev)
        web001 = [a for a in self.store.alerts_since(0) if a["rule_id"] == "WEB-001"]
        self.assertEqual(len(web001), 1)
        self.assertEqual(web001[0]["count"], 5)

    def test_new_value_respects_learning(self):
        engine = Engine(load_rules(), self.store, learning_until=10 ** 12)
        ev = parse_line("auth", "Sep 24 09:01:00 vps sshd[1]: Accepted publickey for ana from 198.51.100.7 port 1 ssh2")
        engine.process(ev)
        self.assertNotIn("SSH-005", self.rules_fired())


class CollectorTest(unittest.TestCase):
    def test_tailer_reads_only_new_lines_and_handles_rotation(self):
        store = Store(":memory:")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.log")
            with open(path, "w") as fh:
                fh.write("velha\n")
            tailer = FileTailer(path, "auth", store)
            self.assertEqual(tailer.read_lines(), [])
            with open(path, "a") as fh:
                fh.write("nova\n")
            self.assertEqual(tailer.read_lines(), ["nova"])
            os.remove(path)
            with open(path, "w") as fh:
                fh.write("rotacionada\n")
            self.assertEqual(tailer.read_lines(), ["rotacionada"])

    def test_fim_detects_change(self):
        store = Store(":memory:")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "authorized_keys")
            with open(path, "w") as fh:
                fh.write("chave1\n")
            fim = FimScanner([os.path.join(tmp, "*")], store)
            self.assertEqual(fim.scan(), [])
            with open(path, "a") as fh:
                fh.write("chave2\n")
            events = fim.scan()
            self.assertEqual(events[0]["change"], "alterado")


class SanitizeTest(unittest.TestCase):
    def test_removes_dashes_and_emojis(self):
        text = sanitize("Risco alto \u2014 agir agora \U0001F6A8")
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\U0001F6A8", text)


if __name__ == "__main__":
    unittest.main()
