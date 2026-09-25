"""Armazenamento em SQLite.

Decisao de projeto para economizar disco: eventos normais NAO sao gravados um
a um. Eles viram apenas contadores por hora (tabela stats). Somente eventos que
geram alerta novo sao gravados na integra. Isso mantem o banco pequeno mesmo em
servidores com muito trafego.
"""

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS seen (
    rule_id TEXT,
    value TEXT,
    first_ts REAL,
    PRIMARY KEY (rule_id, value)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL,
    source TEXT,
    etype TEXT,
    ip TEXT,
    user TEXT,
    classificacao TEXT,
    summary TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts REAL,
    last_ts REAL,
    rule_id TEXT,
    severity TEXT,
    title TEXT,
    mitre TEXT,
    ip TEXT,
    user TEXT,
    detail TEXT,
    count INTEGER DEFAULT 1,
    event_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
CREATE TABLE IF NOT EXISTS stats (
    hour INTEGER,
    source TEXT,
    etype TEXT,
    total INTEGER,
    suspicious INTEGER,
    PRIMARY KEY (hour, source, etype)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    day TEXT,
    created REAL,
    ai INTEGER,
    content TEXT
);
"""


class Store:
    def __init__(self, path):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA cache_size=-2000")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._stats = {}

    # chave e valor simples, usado para estado interno
    def get(self, key, default=None):
        row = self.db.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
        if row is None:
            return default
        return json.loads(row["v"])

    def set(self, key, value):
        self.db.execute(
            "INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, json.dumps(value)),
        )

    def seen_add(self, rule_id, value, ts):
        cur = self.db.execute(
            "INSERT OR IGNORE INTO seen (rule_id, value, first_ts) VALUES (?, ?, ?)",
            (rule_id, value, ts),
        )
        return cur.rowcount == 1

    def add_event(self, ev):
        cur = self.db.execute(
            "INSERT INTO events (ts, source, etype, ip, user, classificacao, summary, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev.get("ts"),
                ev.get("source"),
                ev.get("etype"),
                ev.get("ip"),
                ev.get("user"),
                ev.get("classificacao"),
                ev.get("summary"),
                (ev.get("raw") or "")[:500],
            ),
        )
        return cur.lastrowid

    def add_alert(self, alert):
        cur = self.db.execute(
            "INSERT INTO alerts (ts, last_ts, rule_id, severity, title, mitre, ip, user, detail, count, event_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert["ts"],
                alert["ts"],
                alert["rule_id"],
                alert["severity"],
                alert["title"],
                alert["mitre"],
                alert.get("ip"),
                alert.get("user"),
                alert.get("detail"),
                alert.get("count", 1),
                alert.get("event_id"),
            ),
        )
        return cur.lastrowid

    def bump_alert(self, alert_id, ts, count=1):
        self.db.execute(
            "UPDATE alerts SET count = count + ?, last_ts = ? WHERE id = ?",
            (count, ts, alert_id),
        )

    def count_stat(self, ts, source, etype, suspicious):
        key = (int(ts // 3600) * 3600, source or "", etype or "")
        total, susp = self._stats.get(key, (0, 0))
        self._stats[key] = (total + 1, susp + (1 if suspicious else 0))

    def flush(self):
        for (hour, source, etype), (total, susp) in self._stats.items():
            self.db.execute(
                "INSERT INTO stats (hour, source, etype, total, suspicious) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(hour, source, etype) DO UPDATE SET "
                "total = total + excluded.total, suspicious = suspicious + excluded.suspicious",
                (hour, source, etype, total, susp),
            )
        self._stats = {}
        self.db.commit()

    def prune(self, retention):
        now = time.time()
        self.db.execute("DELETE FROM events WHERE ts < ?", (now - retention["events_days"] * 86400,))
        self.db.execute("DELETE FROM alerts WHERE ts < ?", (now - retention["alerts_days"] * 86400,))
        self.db.execute("DELETE FROM stats WHERE hour < ?", (now - retention["stats_days"] * 86400,))
        self.db.execute("DELETE FROM reports WHERE created < ?", (now - retention["alerts_days"] * 86400,))
        self.db.commit()

    # consultas usadas por CLI e relatorios
    def alerts_since(self, since, min_rank=1):
        from .config import SEV_RANK

        rows = self.db.execute(
            "SELECT * FROM alerts WHERE last_ts >= ? ORDER BY ts DESC", (since,)
        ).fetchall()
        return [dict(r) for r in rows if SEV_RANK.get(r["severity"], 1) >= min_rank]

    def stats_since(self, since):
        rows = self.db.execute(
            "SELECT source, etype, SUM(total) AS total, SUM(suspicious) AS suspicious "
            "FROM stats WHERE hour >= ? GROUP BY source, etype ORDER BY total DESC",
            (int(since // 3600) * 3600,),
        ).fetchall()
        return [dict(r) for r in rows]

    def save_report(self, day, content, used_ai):
        self.db.execute(
            "INSERT INTO reports (day, created, ai, content) VALUES (?, ?, ?, ?)",
            (day, time.time(), 1 if used_ai else 0, content),
        )
        self.db.commit()

    def close(self):
        self.flush()
        self.db.close()
