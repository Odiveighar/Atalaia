"""Coletores de dados do servidor.

FileTailer   acompanha arquivos de log (sobrevive a rotacao e reinicio)
FimScanner   monitoramento de integridade de arquivos criticos (hash sha256)
NetScanner   portas escutando no servidor, lidas direto de /proc/net
"""

import glob
import hashlib
import os
import time

MAX_READ_BYTES = 1024 * 1024
MAX_HASH_BYTES = 50 * 1024 * 1024


class FileTailer:
    """Le somente as linhas novas de um arquivo, guardando o offset no banco."""

    def __init__(self, path, stype, store, from_start=False):
        self.path = path
        self.stype = stype
        self.store = store
        self.from_start = from_start
        self.state_key = "tail:" + path
        self.state = store.get(self.state_key)

    def _head(self, size):
        """Primeiros bytes do arquivo, para detectar rotacao mesmo com inode reaproveitado."""
        try:
            with open(self.path, "rb") as fh:
                return hashlib.sha1(fh.read(min(size, 256))).hexdigest(), min(size, 256)
        except OSError:
            return "", 0

    def read_lines(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        if self.state is None:
            offset = 0 if self.from_start else st.st_size
            head, head_len = self._head(st.st_size)
            self.state = {"inode": st.st_ino, "offset": offset, "head": head, "head_len": head_len}
            self.store.set(self.state_key, self.state)
        rotated = st.st_ino != self.state["inode"] or st.st_size < self.state["offset"]
        if not rotated and self.state.get("head_len"):
            with open(self.path, "rb") as fh:
                current = hashlib.sha1(fh.read(self.state["head_len"])).hexdigest()
            rotated = current != self.state.get("head")
        if rotated:
            # arquivo foi rotacionado ou truncado: recomeca do inicio do novo arquivo
            self.state = {"inode": st.st_ino, "offset": 0, "head": "", "head_len": 0}
        if st.st_size == self.state["offset"]:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.state["offset"])
                data = fh.read(MAX_READ_BYTES)
        except OSError:
            return []
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            if len(data) >= MAX_READ_BYTES:
                self.state["offset"] += len(data)
                self.store.set(self.state_key, self.state)
            return []
        chunk = data[: last_nl + 1]
        self.state["offset"] += len(chunk)
        if self.state.get("head_len", 0) < 256:
            self.state["head"], self.state["head_len"] = self._head(self.state["offset"])
        self.store.set(self.state_key, self.state)
        return chunk.decode("utf-8", "replace").splitlines()


def sha256_file(path):
    h = hashlib.sha256()
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return "grande-demais"
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


class FimScanner:
    def __init__(self, patterns, store):
        self.patterns = patterns
        self.store = store

    def _current(self):
        files = {}
        for pattern in self.patterns:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    digest = sha256_file(path)
                    if digest:
                        files[path] = digest
        return files

    def scan(self):
        now = time.time()
        current = self._current()
        known = self.store.get("fim:hashes")
        self.store.set("fim:hashes", current)
        if known is None:
            return []
        events = []
        for path, digest in current.items():
            if path not in known:
                events.append(self._event(now, path, "criado"))
            elif known[path] != digest:
                events.append(self._event(now, path, "alterado"))
        for path in known:
            if path not in current:
                events.append(self._event(now, path, "removido"))
        return events

    @staticmethod
    def _event(ts, path, change):
        return {
            "ts": ts,
            "source": "fim",
            "etype": "fim_change",
            "path": path,
            "change": change,
            "summary": "Arquivo critico %s: %s" % (change, path),
            "raw": "%s %s" % (change, path),
        }


def _hex_addr_is_loopback(addr):
    if len(addr) == 8:
        return addr.endswith("7F")
    if addr == "00000000000000000000000001000000":
        return True
    return addr.startswith("0000000000000000FFFF0000") and addr.endswith("7F")


def _hex_addr_is_any(addr):
    return set(addr) == {"0"}


def listening_ports(proc_root="/proc/net"):
    result = set()
    tables = (("tcp", "tcp", "0A"), ("tcp6", "tcp", "0A"), ("udp", "udp", "07"), ("udp6", "udp", "07"))
    for fname, proto, listen_state in tables:
        try:
            with open(os.path.join(proc_root, fname), "r") as fh:
                lines = fh.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != listen_state:
                continue
            addr, port_hex = parts[1].rsplit(":", 1)
            if _hex_addr_is_loopback(addr):
                scope = "local"
            elif _hex_addr_is_any(addr):
                scope = "publica"
            else:
                scope = "interface"
            result.add((proto, int(port_hex, 16), scope))
    return result


class NetScanner:
    def __init__(self, proc_root="/proc/net"):
        self.proc_root = proc_root
        self.previous = None

    def scan(self):
        now = time.time()
        current = listening_ports(self.proc_root)
        new = current if self.previous is None else current - self.previous
        self.previous = current
        events = []
        for proto, port, scope in sorted(new):
            events.append({
                "ts": now,
                "source": "rede",
                "etype": "net_listen",
                "proto": proto,
                "port": str(port),
                "scope": scope,
                "summary": "Porta %s/%s escutando (%s)" % (proto, port, scope),
                "raw": "%s %s %s" % (proto, port, scope),
            })
        return events
