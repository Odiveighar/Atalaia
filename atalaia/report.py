"""Relatorio diario.

Se a IA estiver configurada, o agente escreve um relatorio em linguagem de dono
de empresa, com nivel de risco, incidentes, provaveis falsos positivos e
sugestoes priorizadas. Sem IA, o Atalaia gera um relatorio objetivo por conta
propria, para o produto nunca depender de um servico externo.
"""

import json
import time
from collections import Counter, defaultdict
from datetime import datetime

from .ai import sanitize
from .collectors import listening_ports
from .config import SEV_RANK

SYSTEM_PROMPT = """Voce e o agente de seguranca do Atalaia, um sistema de monitoramento para pequenas e medias empresas brasileiras.
Voce recebe o resumo das ultimas 24 horas de um servidor e escreve o relatorio diario.

Regras de escrita:
1. Portugues do Brasil, direto, sem emojis e sem travessao.
2. Primeiro um resumo executivo de 3 a 5 linhas para o dono da empresa, que nao e tecnico.
3. Depois a classificacao de risco do dia: BAIXO, MODERADO, ALTO ou CRITICO, com uma frase justificando.
4. Depois os incidentes relevantes, do mais grave para o menos grave, explicando o que aconteceu e se houve sucesso do atacante.
5. Aponte alertas que parecem falso positivo e sugira o ajuste de regra (exemplo: adicionar IP na whitelist_ips ou aumentar count).
6. Termine com no maximo 5 sugestoes priorizadas. Quando fizer sentido, inclua o comando Linux exato.
7. Nunca invente eventos que nao estao nos dados. Se o dia foi tranquilo, diga isso com clareza.
8. Varreduras automaticas da internet sao normais em qualquer servidor publico. Nao trate isso como invasao, a menos que haja sinal de sucesso."""


def build_context(store, cfg, since, offline=False):
    alerts = store.alerts_since(since)
    stats = store.stats_since(since)
    by_rule = defaultdict(lambda: {"ocorrencias": 0, "ips": set(), "severidade": "", "titulo": "", "mitre": ""})
    ip_counter = Counter()
    for a in alerts:
        item = by_rule[a["rule_id"]]
        item["ocorrencias"] += a["count"]
        item["severidade"] = a["severity"]
        item["titulo"] = a["title"]
        item["mitre"] = a["mitre"]
        if a["ip"]:
            item["ips"].add(a["ip"])
            ip_counter[a["ip"]] += a["count"]
    regras = []
    for rule_id, item in sorted(by_rule.items(), key=lambda kv: -SEV_RANK.get(kv[1]["severidade"], 1)):
        regras.append({
            "regra": rule_id,
            "titulo": item["titulo"],
            "severidade": item["severidade"],
            "mitre": item["mitre"],
            "ocorrencias": item["ocorrencias"],
            "ips_distintos": len(item["ips"]),
            "exemplos_ip": sorted(item["ips"])[:5],
        })
    graves = [
        {k: a.get(k) for k in ("rule_id", "severity", "ip", "user", "detail", "count")}
        | {"hora": datetime.fromtimestamp(a["ts"]).strftime("%d/%m %H:%M")}
        for a in alerts if SEV_RANK.get(a["severity"], 1) >= SEV_RANK["alta"]
    ][:30]
    total = sum(s["total"] for s in stats)
    suspeitos = sum(s["suspicious"] for s in stats)
    if offline:
        portas = []
        stamps = [a["ts"] for a in alerts] or [time.time()]
        inicio, fim = min(stamps), max(stamps)
    else:
        portas = sorted({"%s/%s" % (p, n) for p, n, scope in listening_ports() if scope != "local"})
        inicio, fim = since, time.time()
    return {
        "servidor": cfg["host_name"],
        "empresa": cfg["ai"].get("company_name") or "",
        "periodo": "%s ate %s" % (datetime.fromtimestamp(inicio).strftime("%d/%m/%Y %H:%M"),
                                  datetime.fromtimestamp(fim).strftime("%d/%m/%Y %H:%M")),
        "modo": "analise offline de arquivos de log" if offline else "monitoramento continuo",
        "eventos_analisados": total,
        "eventos_suspeitos": suspeitos,
        "eventos_por_tipo": [{"fonte": s["source"], "tipo": s["etype"], "total": s["total"],
                              "suspeitos": s["suspicious"]} for s in stats[:15]],
        "alertas_por_regra": regras,
        "alertas_graves": graves,
        "ips_mais_ativos": ip_counter.most_common(10),
        "portas_expostas": portas,
        "whitelist_atual": cfg.get("whitelist_ips", []),
    }


def fallback_report(ctx):
    graves = [r for r in ctx["alertas_por_regra"] if SEV_RANK.get(r["severidade"], 1) >= SEV_RANK["alta"]]
    criticos = [r for r in ctx["alertas_por_regra"] if r["severidade"] == "critica"]
    if criticos:
        risco = "CRITICO"
    elif graves:
        risco = "ALTO"
    elif ctx["alertas_por_regra"]:
        risco = "MODERADO"
    else:
        risco = "BAIXO"
    lines = [
        "RELATORIO DIARIO ATALAIA",
        "Servidor: %s" % ctx["servidor"],
        "Periodo: %s" % ctx["periodo"],
        "",
        "Nivel de risco: %s" % risco,
        "Eventos analisados: %s | Suspeitos: %s" % (ctx["eventos_analisados"], ctx["eventos_suspeitos"]),
        "",
        "Alertas por regra:",
    ]
    if not ctx["alertas_por_regra"]:
        lines.append("  Nenhum alerta no periodo.")
    for r in ctx["alertas_por_regra"]:
        lines.append("  [%s] %s %s: %s ocorrencias, %s IPs (%s)" % (
            r["severidade"].upper(), r["regra"], r["titulo"], r["ocorrencias"], r["ips_distintos"], r["mitre"]))
    if ctx["ips_mais_ativos"]:
        lines.append("")
        lines.append("IPs mais ativos:")
        for ip, count in ctx["ips_mais_ativos"]:
            lines.append("  %s: %s ocorrencias" % (ip, count))
    lines.append("")
    if ctx["modo"] == "monitoramento continuo":
        lines.append("Portas expostas: %s" % (", ".join(ctx["portas_expostas"]) or "nenhuma detectada"))
        lines.append("")
    lines.append("Configure a IA (secao ai no config.json) para receber analise e sugestoes personalizadas.")
    return "\n".join(lines)


def generate_report(store, cfg, ai=None, hours=24, offline=False):
    since = 0 if offline else time.time() - hours * 3600
    ctx = build_context(store, cfg, since, offline)
    if ai is not None and ai.available():
        try:
            prompt = "Dados do periodo em JSON:\n" + json.dumps(ctx, ensure_ascii=False, indent=1)
            text = ai.complete(SYSTEM_PROMPT, prompt, max_tokens=2500)
            header = "RELATORIO DIARIO ATALAIA | %s | %s\n\n" % (ctx["servidor"], ctx["periodo"])
            return sanitize(header + text), True
        except Exception as exc:
            text = fallback_report(ctx) + "\n\n(IA indisponivel: %s)" % exc
            return text, False
    return fallback_report(ctx), False
