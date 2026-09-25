"""Linha de comando do Atalaia.

  atalaia run          inicia o monitoramento (usado pelo systemd)
  atalaia check        valida configuracao, fontes e permissoes
  atalaia status       resumo das ultimas 24 horas
  atalaia alerts       lista alertas
  atalaia report       gera o relatorio agora
  atalaia analyze      analisa arquivos de log offline (diagnostico para clientes)
  atalaia rules        lista as regras ativas
  atalaia test-notify  envia uma mensagem de teste nos canais configurados
"""

import argparse
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime

from . import __version__
from .ai import AIClient
from .config import SEV_RANK, load_config
from .engine import Engine, load_rules
from .parsers import parse_line
from .report import generate_report
from .storage import Store

DEFAULT_CONFIG = "/etc/atalaia/config.json"


def _cfg(args):
    path = args.config
    if path == DEFAULT_CONFIG and not os.path.exists(path):
        path = None
    return load_config(path)


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M:%S")


def _print_alerts(alerts):
    if not alerts:
        print("Nenhum alerta.")
        return
    for a in alerts:
        print("%s  %-8s %-8s x%-4s %-15s %s" % (
            _fmt_ts(a["ts"]), a["severity"].upper(), a["rule_id"], a["count"], a.get("ip") or "-", a["title"]))
        print("    %s" % (a.get("detail") or ""))


def cmd_run(args):
    from .agent import Agent
    Agent(_cfg(args)).run()


def cmd_check(args):
    cfg = _cfg(args)
    ok = True
    print("Atalaia %s | host %s" % (__version__, cfg["host_name"]))
    for src in cfg["sources"]:
        path = src["path"]
        if not os.path.exists(path):
            print("  [aviso] fonte %s nao encontrada: %s" % (src["type"], path))
        elif not os.access(path, os.R_OK):
            print("  [erro]  sem permissao de leitura: %s" % path)
            ok = False
        else:
            print("  [ok]    %s: %s" % (src["type"], path))
    try:
        os.makedirs(cfg["data_dir"], exist_ok=True)
        print("  [ok]    pasta de dados: %s" % cfg["data_dir"])
    except OSError as exc:
        print("  [erro]  pasta de dados: %s" % exc)
        ok = False
    rules = load_rules(cfg)
    print("  [ok]    %d regras carregadas (%d ativas)" % (len(rules), sum(1 for r in rules if r.enabled)))
    ai = AIClient(cfg["ai"])
    if cfg["ai"].get("enabled"):
        print("  [%s]    IA: %s" % ("ok" if ai.available() else "erro",
                                    "chave encontrada" if ai.api_key else "variavel %s vazia" % cfg["ai"]["api_key_env"]))
    else:
        print("  [info]  IA desativada, relatorios serao gerados sem IA")
    sys.exit(0 if ok else 1)


def cmd_status(args):
    cfg = _cfg(args)
    store = Store(os.path.join(cfg["data_dir"], "atalaia.db"))
    hb = store.get("heartbeat")
    print("Ultimo sinal do agente: %s" % (_fmt_ts(hb) if hb else "nunca"))
    since = time.time() - 86400
    stats = store.stats_since(since)
    total = sum(s["total"] for s in stats)
    susp = sum(s["suspicious"] for s in stats)
    print("Ultimas 24h: %d eventos analisados, %d suspeitos" % (total, susp))
    alerts = store.alerts_since(since)
    sev = Counter(a["severity"] for a in alerts)
    print("Alertas: " + ", ".join("%s=%d" % (s, sev.get(s, 0)) for s in ("critica", "alta", "media", "baixa")))
    base = os.path.join(cfg["data_dir"], "atalaia.db")
    size = sum(os.path.getsize(base + ext) for ext in ("", "-wal", "-shm") if os.path.exists(base + ext))
    print("Tamanho do banco: %.1f KB" % (size / 1024.0))


def cmd_alerts(args):
    cfg = _cfg(args)
    store = Store(os.path.join(cfg["data_dir"], "atalaia.db"))
    alerts = store.alerts_since(time.time() - args.hours * 3600, SEV_RANK.get(args.min, 1))
    _print_alerts(alerts[: args.limit])


def cmd_report(args):
    cfg = _cfg(args)
    store = Store(os.path.join(cfg["data_dir"], "atalaia.db"))
    ai = AIClient(cfg["ai"])
    text, used_ai = generate_report(store, cfg, ai, hours=args.hours)
    print(text)
    if args.send:
        from .notify import Notifier
        n = Notifier(cfg, ai)
        n.send_text(text)
        n.wait()


def cmd_analyze(args):
    """Analisa logs antigos sem instalar nada. Otimo para diagnostico gratuito."""
    cfg = _cfg(args)
    store = Store(":memory:")
    engine = Engine(load_rules(cfg), store, whitelist=cfg.get("whitelist_ips"), skip_kinds={"new_value"})
    total = Counter()
    for item in args.files:
        if ":" not in item:
            print("Formato esperado tipo:caminho, exemplo auth:/var/log/auth.log")
            sys.exit(2)
        stype, path = item.split(":", 1)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ev = parse_line(stype, line)
                if ev:
                    engine.process(ev)
                    total[ev["classificacao"]] += 1
    store.flush()
    print("Eventos: %d normais, %d suspeitos, %d criticos\n" % (total["normal"], total["suspeito"], total["critico"]))
    alerts = store.alerts_since(0)
    alerts.sort(key=lambda a: (-SEV_RANK.get(a["severity"], 1), a["ts"]))
    _print_alerts(alerts)
    if args.report:
        print("\n" + "=" * 60 + "\n")
        text, _ = generate_report(store, cfg, AIClient(cfg["ai"]), offline=True)
        print(text)


def cmd_rules(args):
    for r in load_rules(_cfg(args)):
        print("%-8s %-8s %-10s %-3s %s" % (r.id, r.severity, r.kind, "on" if r.enabled else "off", r.title))


def cmd_test_notify(args):
    from .notify import Notifier
    cfg = _cfg(args)
    n = Notifier(cfg)
    if not n.configured():
        print("Nenhum canal configurado na secao notify.")
        sys.exit(1)
    n.send_text("[ATALAIA] Teste de notificacao do servidor %s. Se voce recebeu, esta funcionando." % cfg["host_name"])
    n.wait()
    print("Mensagem de teste enviada. Confira os logs se nao chegar.")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="atalaia", description="Monitoramento de seguranca leve para servidores")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("-v", "--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run").set_defaults(func=cmd_run)
    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("status").set_defaults(func=cmd_status)
    p = sub.add_parser("alerts")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--min", default="baixa", choices=list(SEV_RANK))
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_alerts)
    p = sub.add_parser("report")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--send", action="store_true")
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("analyze")
    p.add_argument("files", nargs="+", help="tipo:caminho, tipos: auth, http, firewall")
    p.add_argument("--report", action="store_true")
    p.set_defaults(func=cmd_analyze)
    sub.add_parser("rules").set_defaults(func=cmd_rules)
    sub.add_parser("test-notify").set_defaults(func=cmd_test_notify)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
