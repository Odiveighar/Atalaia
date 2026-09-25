"""Loop principal do Atalaia.

Um unico processo, uma unica thread de leitura (mais a thread de notificacao).
Nada de indexador pesado: o consumo tipico fica entre 20 e 40 MB de RAM.
"""

import logging
import os
import signal
import time
from datetime import datetime

from .ai import AIClient
from .collectors import FileTailer, FimScanner, NetScanner
from .engine import Engine, load_rules
from .notify import Notifier
from .parsers import parse_line
from .report import generate_report
from .storage import Store

log = logging.getLogger("atalaia")


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.running = True
        self.store = Store(os.path.join(cfg["data_dir"], "atalaia.db"))
        install_ts = self.store.get("install_ts")
        if install_ts is None:
            install_ts = time.time()
            self.store.set("install_ts", install_ts)
        self.ai = AIClient(cfg["ai"])
        self.notifier = Notifier(cfg, self.ai)
        self.engine = Engine(
            load_rules(cfg),
            self.store,
            whitelist=cfg.get("whitelist_ips"),
            learning_until=install_ts + cfg["learning_hours"] * 3600,
            on_alert=self._on_alert,
        )
        self.tailers = [FileTailer(s["path"], s["type"], self.store, s.get("from_start", False))
                        for s in cfg["sources"]]
        self.fim = FimScanner(cfg["fim"]["paths"], self.store) if cfg["fim"]["enabled"] else None
        self.net = NetScanner() if cfg["network"]["enabled"] else None
        self.store.db.commit()

    def _on_alert(self, alert):
        log.warning("[%s] %s %s | %s", alert["severity"].upper(), alert["rule_id"], alert["title"], alert["detail"])
        self.notifier.alert(alert)

    def _stop(self, *_):
        self.running = False

    def _handle(self, ev):
        ev["host"] = self.cfg["host_name"]
        self.engine.process(ev)

    def maybe_report(self):
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        if now.hour < int(self.cfg["ai"].get("report_hour", 7)):
            return
        if self.store.get("last_report_day") == today:
            return
        self.store.set("last_report_day", today)
        self.store.flush()
        text, used_ai = generate_report(self.store, self.cfg, self.ai)
        self.store.save_report(today, text, used_ai)
        reports_dir = os.path.join(self.cfg["data_dir"], "relatorios")
        os.makedirs(reports_dir, exist_ok=True)
        with open(os.path.join(reports_dir, today + ".txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        self.notifier.send_text(text)
        log.info("Relatorio diario gerado (IA: %s)", "sim" if used_ai else "nao")

    def run(self):
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        log.info("Atalaia iniciado em %s com %d fontes de log", self.cfg["host_name"], len(self.tailers))
        next_fim = next_net = next_cleanup = 0.0
        poll = float(self.cfg["poll_interval"])
        while self.running:
            now = time.time()
            for tailer in self.tailers:
                # drena ate 16 MB por fonte por ciclo, sem carregar tudo na memoria
                for _ in range(16):
                    lines = tailer.read_lines()
                    if not lines:
                        break
                    for line in lines:
                        ev = parse_line(tailer.stype, line)
                        if ev:
                            self._handle(ev)
            if self.fim and now >= next_fim:
                for ev in self.fim.scan():
                    self._handle(ev)
                next_fim = now + self.cfg["fim"]["interval"]
            if self.net and now >= next_net:
                for ev in self.net.scan():
                    self._handle(ev)
                next_net = now + self.cfg["network"]["interval"]
            if now >= next_cleanup:
                self.engine.cleanup(now)
                self.store.prune(self.cfg["retention"])
                next_cleanup = now + 3600
            self.store.set("heartbeat", now)
            self.store.flush()
            try:
                self.maybe_report()
            except Exception as exc:
                log.error("Falha ao gerar relatorio: %s", exc)
            time.sleep(poll)
        self.store.close()
        log.info("Atalaia finalizado")
