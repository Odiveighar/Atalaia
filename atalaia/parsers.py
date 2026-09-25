"""Parsers: transformam linhas de log em eventos normalizados.

Todo evento e um dict com pelo menos: ts, source, etype, summary, raw.
Campos opcionais: ip, user, method, path, status, ua, port, dpt, cmd, group.

Tipos de fonte suportados no MVP:
  auth      /var/log/auth.log ou /var/log/secure (SSH, sudo, criacao de usuario)
  http      nginx, apache, traefik (formato combined ou JSON do traefik)
  firewall  ufw.log, kern.log ou syslog com linhas do iptables (SRC= DPT=)
"""

import json
import re
import time
from datetime import datetime
from urllib.parse import unquote_plus

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}

RE_SYSLOG_CLASSIC = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)")
RE_SYSLOG_ISO = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)")

RE_SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F\.:]+)")
RE_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F\.:]+)")
RE_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F\.:]+)")
RE_SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
RE_SUDO_FAIL = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?(?:incorrect password attempts|NOT in sudoers)")
RE_USERADD = re.compile(r"useradd\[\d+\]: new user: name=(?P<user>[^,\s]+)")
RE_GROUP_1 = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
RE_GROUP_2 = re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")

RE_HTTP = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<ruser>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

RE_FW = re.compile(r"SRC=(?P<ip>[0-9a-fA-F\.:]+) DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:.*?DPT=(?P<dpt>\d+))?")


def parse_syslog_ts(line, now=None):
    now = now or time.time()
    m = RE_SYSLOG_ISO.match(line)
    if m:
        iso = m.group("iso").replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(iso).timestamp()
        except ValueError:
            return now
    m = RE_SYSLOG_CLASSIC.match(line)
    if m:
        year = datetime.fromtimestamp(now).year
        try:
            dt = datetime(year, MONTHS[m.group("mon")], int(m.group("day")),
                          int(m.group("h")), int(m.group("m")), int(m.group("s")))
        except (KeyError, ValueError):
            return now
        ts = dt.timestamp()
        if ts > now + 86400:
            ts = dt.replace(year=year - 1).timestamp()
        return ts
    return now


def _base(source, etype, ts, raw, summary, **fields):
    ev = {"ts": ts, "source": source, "etype": etype, "raw": raw.strip()[:500], "summary": summary}
    for key, value in fields.items():
        if value not in (None, ""):
            ev[key] = value
    return ev


def parse_auth(line):
    ts = parse_syslog_ts(line)
    m = RE_SSH_OK.search(line)
    if m:
        return _base("auth", "ssh_success", ts, line,
                     "Login SSH aceito (%s) para %s vindo de %s" % (m.group("method"), m.group("user"), m.group("ip")),
                     ip=m.group("ip"), user=m.group("user"), method=m.group("method"))
    m = RE_SSH_FAIL.search(line)
    if m:
        return _base("auth", "ssh_fail", ts, line,
                     "Falha de login SSH para %s vindo de %s" % (m.group("user") or "?", m.group("ip")),
                     ip=m.group("ip"), user=m.group("user"))
    m = RE_SSH_INVALID.search(line)
    if m:
        return _base("auth", "ssh_invalid_user", ts, line,
                     "Tentativa SSH com usuario inexistente %s vindo de %s" % (m.group("user") or "?", m.group("ip")),
                     ip=m.group("ip"), user=m.group("user"))
    m = RE_SUDO_FAIL.search(line)
    if m:
        return _base("auth", "sudo_fail", ts, line,
                     "Falha de sudo pelo usuario %s" % m.group("user"), user=m.group("user"))
    m = RE_SUDO.search(line)
    if m:
        return _base("auth", "sudo", ts, line,
                     "Sudo por %s: %s" % (m.group("user"), m.group("cmd").strip()[:200]),
                     user=m.group("user"), cmd=m.group("cmd").strip())
    m = RE_USERADD.search(line)
    if m:
        return _base("auth", "user_created", ts, line,
                     "Novo usuario criado no sistema: %s" % m.group("user"), user=m.group("user"))
    m = RE_GROUP_1.search(line) or RE_GROUP_2.search(line)
    if m:
        return _base("auth", "group_add", ts, line,
                     "Usuario %s adicionado ao grupo %s" % (m.group("user"), m.group("group")),
                     user=m.group("user"), group=m.group("group"))
    return None


def _http_ts(value):
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        return time.time()


def _http_event(line, ip, method, path, status, ua, ts):
    decoded = unquote_plus(path or "")
    return _base("http", "http", ts, line,
                 "%s %s %s de %s" % (method or "-", decoded[:150], status, ip),
                 ip=ip, method=method, path=decoded, status=str(status), ua=ua)


def parse_http(line):
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            return None
        ip = data.get("ClientHost") or data.get("remote_addr") or data.get("ip")
        method = data.get("RequestMethod") or data.get("method")
        path = data.get("RequestPath") or data.get("uri") or data.get("path")
        status = data.get("DownstreamStatus") or data.get("OriginStatus") or data.get("status") or 0
        ua = data.get("request_User-Agent") or data.get("http_user_agent") or data.get("user_agent")
        return _http_event(line, ip, method, path, status, ua, time.time())
    m = RE_HTTP.match(stripped)
    if not m:
        return None
    parts = m.group("req").split(" ")
    if len(parts) >= 2:
        method, path = parts[0], parts[1]
    else:
        method, path = "", m.group("req")
    return _http_event(line, m.group("ip"), method, path, m.group("status"), m.group("ua"), _http_ts(m.group("time")))


def parse_firewall(line):
    if "SRC=" not in line:
        return None
    if "ALLOW" in line and "BLOCK" not in line:
        return None
    m = RE_FW.search(line)
    if not m:
        return None
    return _base("firewall", "fw_block", parse_syslog_ts(line), line,
                 "Conexao bloqueada de %s para porta %s/%s" % (m.group("ip"), m.group("dpt") or "?", m.group("proto")),
                 ip=m.group("ip"), dpt=m.group("dpt"), proto=m.group("proto"))


PARSERS = {"auth": parse_auth, "http": parse_http, "firewall": parse_firewall}


def parse_line(source_type, line):
    parser = PARSERS.get(source_type)
    if parser is None or not line.strip():
        return None
    return parser(line)
