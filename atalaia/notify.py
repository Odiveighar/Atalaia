"""Envio de alertas e relatorios.

Canais: Telegram, WhatsApp via Evolution API e webhook generico (JSON).
Roda em uma thread separada para nunca travar a leitura de logs, e tem limite
de envio para nao inundar o celular do cliente durante um ataque em massa.
"""

import json
import logging
import queue
import threading
import time
import urllib.request

from .config import SEV_RANK

log = logging.getLogger("atalaia.notify")


def _post_json(url, payload, headers=None, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"content-type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def _chunks(text, size=3800):
    while text:
        yield text[:size]
        text = text[size:]


def format_alert(alert, host, explanation=None):
    lines = [
        "[ATALAIA] ALERTA %s" % alert["severity"].upper(),
        "Servidor: %s" % host,
        "Regra: %s %s" % (alert["rule_id"], alert["title"]),
    ]
    if alert.get("ip"):
        lines.append("IP de origem: %s" % alert["ip"])
    if alert.get("user"):
        lines.append("Usuario: %s" % alert["user"])
    if alert.get("count", 1) > 1:
        lines.append("Ocorrencias: %s" % alert["count"])
    lines.append("MITRE ATT&CK: %s" % alert.get("mitre", ""))
    lines.append("Detalhe: %s" % alert.get("detail", ""))
    if explanation:
        lines.append("")
        lines.append("Analise: %s" % explanation)
    elif alert.get("recommendation"):
        lines.append("O que fazer: %s" % alert["recommendation"])
    return "\n".join(lines)


class Notifier:
    def __init__(self, cfg, ai=None):
        self.cfg = cfg["notify"]
        self.host = cfg["host_name"]
        self.ai = ai
        self.explain = cfg["ai"].get("explain_critical", False)
        self.min_rank = SEV_RANK.get(self.cfg.get("min_severity", "alta"), 3)
        self.max_per_window = int(self.cfg.get("max_per_5min", 10))
        self.sent = []
        self.suppressed = 0
        self.q = queue.Queue(maxsize=500)
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def configured(self):
        tg = self.cfg.get("telegram", {})
        ev = self.cfg.get("evolution", {})
        return bool((tg.get("bot_token") and tg.get("chat_id"))
                    or (ev.get("url") and ev.get("number"))
                    or self.cfg.get("webhook", {}).get("url"))

    def alert(self, alert):
        if SEV_RANK.get(alert["severity"], 1) < self.min_rank or not self.configured():
            return
        try:
            self.q.put_nowait(("alert", alert))
        except queue.Full:
            self.suppressed += 1

    def send_text(self, text):
        if self.configured():
            self.q.put(("text", text))

    def wait(self, timeout=60):
        end = time.time() + timeout
        while not self.q.empty() and time.time() < end:
            time.sleep(0.2)
        time.sleep(0.5)

    def _allowed(self):
        now = time.time()
        self.sent = [t for t in self.sent if t > now - 300]
        if len(self.sent) >= self.max_per_window:
            return False
        self.sent.append(now)
        return True

    def _worker(self):
        while True:
            kind, item = self.q.get()
            try:
                if kind == "text":
                    self._deliver(item, {"type": "report", "host": self.host, "text": item})
                    continue
                if not self._allowed():
                    self.suppressed += 1
                    continue
                text_prefix = ""
                if self.suppressed:
                    text_prefix = "(%s alertas anteriores foram agrupados para evitar excesso de mensagens)\n\n" % self.suppressed
                    self.suppressed = 0
                explanation = None
                if self.ai and self.ai.available() and self.explain and item["severity"] == "critica":
                    try:
                        explanation = self.ai.explain_alert(item, self.host)
                    except Exception as exc:
                        log.warning("IA indisponivel para explicar alerta: %s", exc)
                text = text_prefix + format_alert(item, self.host, explanation)
                payload = dict(item, type="alert", host=self.host, text=text)
                self._deliver(text, payload)
            except Exception as exc:
                log.error("Falha ao notificar: %s", exc)
            finally:
                self.q.task_done()

    def _deliver(self, text, payload):
        tg = self.cfg.get("telegram", {})
        if tg.get("bot_token") and tg.get("chat_id"):
            url = "https://api.telegram.org/bot%s/sendMessage" % tg["bot_token"]
            for part in _chunks(text):
                self._safe(_post_json, url, {"chat_id": tg["chat_id"], "text": part})
        ev = self.cfg.get("evolution", {})
        if ev.get("url") and ev.get("number"):
            url = "%s/message/sendText/%s" % (ev["url"].rstrip("/"), ev.get("instance", ""))
            for part in _chunks(text):
                self._safe(_post_json, url, {"number": ev["number"], "text": part}, {"apikey": ev.get("apikey", "")})
        hook = self.cfg.get("webhook", {}).get("url")
        if hook:
            self._safe(_post_json, hook, payload)

    @staticmethod
    def _safe(func, *args):
        try:
            func(*args)
        except Exception as exc:
            log.error("Canal de notificacao falhou: %s", exc)
