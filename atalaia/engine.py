"""Motor de deteccao.

Cada evento passa pelas regras e sai classificado como:
  normal    nenhuma regra disparou (vira so contador, nao ocupa disco)
  suspeito  alguma regra de severidade baixa, media ou alta disparou
  critico   alguma regra de severidade critica disparou

Tipos de regra (campo "kind"):
  match      dispara quando o evento bate com as condicoes
  threshold  dispara quando N eventos do mesmo grupo ocorrem dentro da janela
  distinct   dispara quando o mesmo grupo gera N valores diferentes na janela
             (exemplo: um IP batendo em 15 portas diferentes = varredura)
  new_value  dispara na primeira vez que uma combinacao aparece
             (exemplo: login de um IP nunca visto). Fica silenciosa durante o
             periodo de aprendizado para reduzir falso positivo.
  sequence   dispara quando outra regra ja disparou para a mesma chave dentro
             da janela (exemplo: forca bruta seguida de login com sucesso)
"""

import ipaddress
import json
import os
import re
import time
from collections import deque

from .config import SEV_RANK

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules", "default.json")


def _compile_conditions(conds):
    compiled = []
    for field, value in (conds or {}).items():
        if field == "etype":
            compiled.append((field, set(value if isinstance(value, list) else [value])))
        else:
            compiled.append((field, re.compile(value, re.IGNORECASE)))
    return compiled


def _conditions_ok(compiled, ev):
    for field, test in compiled:
        if field == "etype":
            if ev.get("etype") not in test:
                return False
        else:
            value = ev.get(field)
            if value is None or not test.search(str(value)):
                return False
    return True


class Rule:
    def __init__(self, data):
        self.id = data["id"]
        self.title = data["title"]
        self.kind = data.get("kind", "match")
        self.severity = data.get("severity", "media")
        self.mitre = data.get("mitre", "")
        self.recommendation = data.get("recommendation", "")
        self.enabled = data.get("enabled", True)
        self.match = _compile_conditions(data.get("match"))
        self.exclude = _compile_conditions(data.get("exclude")) if data.get("exclude") else None
        group_by = data.get("group_by", "ip")
        self.group_by = group_by if isinstance(group_by, list) else [group_by]
        self.count = int(data.get("count", 1))
        self.window = float(data.get("window", 60))
        self.distinct = data.get("distinct")
        self.keys = data.get("keys", [])
        self.requires = data.get("requires")
        self.cooldown = float(data.get("cooldown", 600))

    def key_for(self, ev):
        fields = self.keys if self.kind == "new_value" else self.group_by
        return "|".join(str(ev.get(f, "")) for f in fields)


def load_rules(cfg=None):
    cfg = cfg or {}
    with open(RULES_FILE, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    extra = cfg.get("rules_extra")
    if extra and os.path.exists(extra):
        with open(extra, "r", encoding="utf-8") as fh:
            data.extend(json.load(fh))
    overrides = cfg.get("rules_override", {})
    disabled = set(cfg.get("rules_disabled", []))
    rules = []
    for item in data:
        if item["id"] in overrides:
            item = dict(item, **overrides[item["id"]])
        if item["id"] in disabled:
            item["enabled"] = False
        rules.append(Rule(item))
    return rules


class Engine:
    def __init__(self, rules, store, whitelist=None, learning_until=0, skip_kinds=None, on_alert=None):
        self.rules = rules
        self.store = store
        self.learning_until = learning_until
        self.skip_kinds = set(skip_kinds or [])
        self.on_alert = on_alert
        self.networks = []
        self.whitelist = set()
        for item in whitelist or []:
            if "/" in item:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            else:
                self.whitelist.add(item)
        self.windows = {}
        self.distincts = {}
        self.fired = {}
        self.cooldowns = {}
        self.max_window = max([r.window for r in rules] + [60])
        self.max_seq = max([r.requires.get("within", 0) for r in rules if r.requires] + [3600])

    def _whitelisted(self, ip):
        if ip in self.whitelist:
            return True
        if not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def _evaluate(self, rule, ev, key, ts):
        if rule.kind == "match":
            return True, 1
        if rule.kind == "threshold":
            dq = self.windows.setdefault((rule.id, key), deque())
            dq.append(ts)
            while dq and dq[0] < ts - rule.window:
                dq.popleft()
            if len(dq) >= rule.count:
                total = len(dq)
                dq.clear()
                return True, total
            return False, 0
        if rule.kind == "distinct":
            values = self.distincts.setdefault((rule.id, key), {})
            values[str(ev.get(rule.distinct, ""))] = ts
            for val in [v for v, t in values.items() if t < ts - rule.window]:
                del values[val]
            if len(values) >= rule.count:
                total = len(values)
                values.clear()
                return True, total
            return False, 0
        if rule.kind == "new_value":
            is_new = self.store.seen_add(rule.id, key, ts)
            return (is_new and ts >= self.learning_until), 1
        if rule.kind == "sequence":
            req = rule.requires or {}
            prior = self.fired.get((req.get("rule"), str(ev.get(req.get("key", "ip"), ""))))
            if prior is not None and 0 <= ts - prior <= req.get("within", 3600):
                return True, 1
            return False, 0
        return False, 0

    def process(self, ev):
        """Classifica o evento e devolve a lista de alertas NOVOS gerados."""
        ts = ev.get("ts") or time.time()
        ip = ev.get("ip")
        triggered = []
        if not (ip and self._whitelisted(ip)):
            for rule in self.rules:
                if not rule.enabled or rule.kind in self.skip_kinds:
                    continue
                if not _conditions_ok(rule.match, ev):
                    continue
                if rule.exclude and _conditions_ok(rule.exclude, ev):
                    continue
                key = rule.key_for(ev)
                hit, count = self._evaluate(rule, ev, key, ts)
                if hit:
                    self.fired[(rule.id, key)] = ts
                    triggered.append((rule, key, count))

        if not triggered:
            ev["classificacao"] = "normal"
            self.store.count_stat(ts, ev.get("source"), ev.get("etype"), False)
            return []

        top = max(SEV_RANK.get(r.severity, 1) for r, _, _ in triggered)
        ev["classificacao"] = "critico" if top >= SEV_RANK["critica"] else "suspeito"
        ev["regras"] = [r.id for r, _, _ in triggered]
        self.store.count_stat(ts, ev.get("source"), ev.get("etype"), True)

        new_alerts = []
        event_id = None
        for rule, key, count in triggered:
            cd = self.cooldowns.get((rule.id, key))
            if cd and ts - cd[0] < rule.cooldown:
                self.store.bump_alert(cd[1], ts, count)
                continue
            if event_id is None:
                event_id = self.store.add_event(ev)
            alert = {
                "ts": ts,
                "rule_id": rule.id,
                "severity": rule.severity,
                "title": rule.title,
                "mitre": rule.mitre,
                "ip": ev.get("ip"),
                "user": ev.get("user"),
                "detail": ev.get("summary"),
                "count": count,
                "event_id": event_id,
                "recommendation": rule.recommendation,
                "classificacao": ev["classificacao"],
            }
            alert["id"] = self.store.add_alert(alert)
            self.cooldowns[(rule.id, key)] = (ts, alert["id"])
            new_alerts.append(alert)
            if self.on_alert:
                self.on_alert(alert)
        return new_alerts

    def cleanup(self, now=None):
        """Libera memoria de janelas antigas. Chamado periodicamente."""
        now = now or time.time()
        for key in [k for k, dq in self.windows.items() if not dq or dq[-1] < now - self.max_window]:
            del self.windows[key]
        for key in [k for k, vals in self.distincts.items() if not vals or max(vals.values()) < now - self.max_window]:
            del self.distincts[key]
        for key in [k for k, ts in self.fired.items() if ts < now - self.max_seq]:
            del self.fired[key]
        for key in [k for k, cd in self.cooldowns.items() if cd[0] < now - 86400]:
            del self.cooldowns[key]
