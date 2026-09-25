"""Falha se encontrar travessao, meia risca ou emoji em arquivos do projeto."""

import pathlib
import re
import sys

PROIBIDO = re.compile("[\u2013\u2014\u2600-\u27BF\U0001F000-\U0001FAFF]")
EXTENSOES = {".py", ".json", ".md", ".sh", ".toml", ".yml", ".service", ".log"}

erros = 0
raiz = pathlib.Path(__file__).resolve().parent.parent
for arquivo in raiz.rglob("*"):
    if arquivo.suffix not in EXTENSOES or ".git" in arquivo.parts:
        continue
    for numero, linha in enumerate(arquivo.read_text(encoding="utf-8").splitlines(), 1):
        if PROIBIDO.search(linha):
            print("%s:%d: %s" % (arquivo.relative_to(raiz), numero, linha.strip()))
            erros += 1

if erros:
    print("%d linhas com travessao ou emoji" % erros)
    sys.exit(1)
print("Nenhum travessao ou emoji encontrado")
