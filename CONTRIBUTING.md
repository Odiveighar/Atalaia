# Como contribuir

Obrigado pelo interesse em melhorar o Atalaia.

## Formas de ajudar

1. **Relatar falso positivo:** abra uma issue com a regra que disparou, a linha de log (troque IPs e nomes reais) e por que o evento era legítimo.
2. **Propor regra nova:** descreva o ataque, a técnica do MITRE ATT&CK e exemplos de linhas de log.
3. **Adicionar parser:** suporte a novos formatos de log, como Apache error log, Postfix ou journald.
4. **Melhorar a documentação:** exemplos de instalação em outras distribuições e ambientes.

## Regras do código

1. Somente a biblioteca padrão do Python 3.9 ou superior. O agente precisa rodar em qualquer servidor sem instalar nada.
2. Sem travessão e sem emoji em código, documentação e mensagens. O CI reprova se encontrar.
3. Toda regra nova precisa de técnica MITRE, recomendação em português e um teste em `tests/`.
4. Expressões regulares não podem ter backtracking catastrófico. Evite padrões como `(a+)+` e `(.*)*`.
5. Nunca use IPs, domínios ou nomes reais em testes e exemplos. Use as faixas de documentação `192.0.2.0/24`, `198.51.100.0/24` e `203.0.113.0/24`.

## Antes de abrir o pull request

```bash
python3 -m unittest discover -s tests -v
python3 scripts/checar_estilo.py
```

Descreva no pull request o que mudou e por quê. Mudanças pequenas e focadas são revisadas mais rápido.
