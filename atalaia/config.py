"""Carregamento de configuracao do Atalaia.

A configuracao e um arquivo JSON simples. Tudo que nao for informado usa os
valores padrao definidos aqui, entao o arquivo do cliente pode ser minimo.
"""

import copy
import json
import os
import socket

SEVERITIES = ["baixa", "media", "alta", "critica"]
SEV_RANK = {name: i + 1 for i, name in enumerate(SEVERITIES)}

DEFAULTS = {
    "host_name": socket.gethostname(),
    "data_dir": "/var/lib/atalaia",
    "poll_interval": 2,
    "learning_hours": 24,
    "whitelist_ips": ["127.0.0.1", "::1"],
    "sources": [
        {"type": "auth", "path": "/var/log/auth.log"},
        {"type": "http", "path": "/var/log/nginx/access.log"},
        {"type": "http", "path": "/var/log/traefik/access.log"},
        {"type": "firewall", "path": "/var/log/ufw.log"},
    ],
    "fim": {
        "enabled": True,
        "interval": 300,
        "paths": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/sudoers.d/*",
            "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys",
            "/etc/crontab",
            "/etc/cron.d/*",
            "/var/spool/cron/crontabs/*",
            "/etc/systemd/system/*.service",
            "/etc/ld.so.preload",
        ],
    },
    "network": {"enabled": True, "interval": 60},
    "retention": {"events_days": 14, "alerts_days": 90, "stats_days": 90},
    "rules_extra": "",
    "rules_disabled": [],
    "rules_override": {},
    "ai": {
        "enabled": False,
        "model": "claude-haiku-4-5-20251001",
        "api_key_env": "ANTHROPIC_API_KEY",
        "report_hour": 7,
        "explain_critical": True,
        "company_name": "",
    },
    "notify": {
        "min_severity": "alta",
        "max_per_5min": 10,
        "telegram": {"bot_token": "", "chat_id": ""},
        "evolution": {"url": "", "instance": "", "apikey": "", "number": ""},
        "webhook": {"url": ""},
    },
}


def deep_merge(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        if not os.path.exists(path):
            raise FileNotFoundError("Arquivo de configuracao nao encontrado: %s" % path)
        with open(path, "r", encoding="utf-8") as fh:
            deep_merge(cfg, json.load(fh))
    return cfg
