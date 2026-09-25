# Política de segurança

O Atalaia roda com privilégios elevados no servidor. Uma falha nele pode afetar todos que o utilizam, por isso vulnerabilidades são tratadas com prioridade máxima.

## Como relatar

**Não abra issue pública para vulnerabilidades.**

Use o relato privado do GitHub: aba **Security**, botão **Report a vulnerability**.

Inclua, se possível:

1. Versão do Atalaia afetada.
2. Descrição do problema e do impacto.
3. Passos para reproduzir.
4. Sugestão de correção, se tiver.

## O que esperar

| Etapa | Prazo |
|---|---|
| Confirmação de recebimento | até 3 dias |
| Avaliação inicial | até 7 dias |
| Correção de falhas críticas | o mais rápido possível, com prioridade sobre qualquer outra tarefa |

Quem relatar será creditado na nota da versão com a correção, se desejar.

## Escopo

Estão no escopo, por exemplo: execução de código a partir de linhas de log maliciosas, expressões regulares que travem o agente (ReDoS), vazamento de chaves da configuração, escrita fora da pasta de dados e formas de um invasor silenciar o agente sem que isso seja detectado.

Fora do escopo: ataques que exigem acesso root prévio ao servidor, pois nesse cenário o invasor já controla a máquina.
