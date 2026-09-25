"""Cliente minimo para a API da Anthropic usando apenas a biblioteca padrao.

A IA nunca recebe os logs brutos. Ela recebe apenas o resumo agregado do dia
(contagens, alertas e amostras curtas), o que reduz custo e exposicao de dados.
"""

import json
import os
import re
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"

RE_EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF\U00002B00-\U00002BFF\uFE0F\u200D]"
)


def sanitize(text):
    """Remove travessoes e emojis de qualquer texto gerado."""
    text = text.replace(" \u2014 ", ", ").replace("\u2014", ", ")
    text = text.replace(" \u2013 ", ", ").replace("\u2013", "-")
    return RE_EMOJI.sub("", text)


class AIClient:
    def __init__(self, ai_cfg):
        self.cfg = ai_cfg
        self.model = ai_cfg.get("model")
        self.api_key = os.environ.get(ai_cfg.get("api_key_env", "ANTHROPIC_API_KEY"), "")

    def available(self):
        return bool(self.cfg.get("enabled") and self.api_key)

    def complete(self, system, prompt, max_tokens=2000, timeout=90):
        body = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(API_URL, data=body, method="POST", headers={
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
        return sanitize(text.strip())

    def explain_alert(self, alert, host):
        system = (
            "Voce e analista de seguranca de um SOC que atende pequenas empresas brasileiras. "
            "Responda em portugues do Brasil, em no maximo 4 linhas curtas, sem emojis e sem travessao. "
            "Explique o risco para um dono de empresa leigo e diga a primeira acao a tomar."
        )
        prompt = "Servidor: %s\nAlerta: %s" % (host, json.dumps({
            k: alert.get(k) for k in ("rule_id", "title", "severity", "mitre", "ip", "user", "detail", "count")
        }, ensure_ascii=False))
        return self.complete(system, prompt, max_tokens=300, timeout=30)
