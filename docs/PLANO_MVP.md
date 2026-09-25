# Plano do Atalaia: do MVP à receita recorrente

## 0. Fase atual: validação aberta

O agente é publicado como código aberto e gratuito antes de qualquer cobrança. Objetivo: provar que o problema existe e que as pessoas instalam e mantêm o Atalaia rodando.

Critérios para começar a cobrar, definidos antes do lançamento para evitar autoengano:

| Sinal | Meta em 60 dias |
|---|---|
| Instalações confirmadas por usuários | 30 |
| Pessoas que deram feedback detalhado (issue, conversa ou formulário) | 10 |
| Servidores rodando há mais de 30 dias | 10 |
| Pedidos espontâneos de painel, versão gerenciada ou suporte pago | 3 |

Estrelas no GitHub não entram na conta: medem curiosidade, não uso.

O último sinal é o mais importante. Quando alguém pergunta se pode pagar por algo, é hora de cobrar.

## 1. Para quem é

Pequenas e médias empresas que têm pelo menos um servidor exposto na internet e ninguém olhando para ele:

1. Empresas com sistema próprio ou site em VPS (Hostinger, Contabo, DigitalOcean, Locaweb).
2. Escritórios de contabilidade, advocacia e clínicas que usam sistemas web com dados sensíveis.
3. Agências e desenvolvedores freelancers que hospedam sites de vários clientes.
4. Lojas virtuais em WordPress ou WooCommerce hospedadas em VPS.

Essas empresas não pagam Wazuh ou Security Onion porque o custo não é a licença, é a **infraestrutura e a pessoa** para operar. O Atalaia elimina as duas coisas.

## 2. Proposta de valor em uma frase

> Um vigia 24 horas no seu servidor que avisa no WhatsApp quando alguém tenta invadir e manda todo dia um relatório em português que qualquer dono de empresa entende.

Argumentos que funcionam com esse público:

1. **LGPD:** a lei exige medidas de segurança e registro de incidentes. O relatório diário é evidência de diligência.
2. **Custo de uma invasão:** um servidor comprometido vira minerador, disparador de spam ou vazamento de dados de clientes.
3. **Prova imediata:** o diagnóstico offline mostra ataques reais nos logs do próprio cliente na primeira reunião.

## 3. Funil de venda

1. **Isca: diagnóstico gratuito.** Peça os arquivos `auth.log` e `access.log` do cliente, rode `atalaia analyze ... --report` e entregue o resultado. Quase todo servidor público tem centenas de tentativas de força bruta por dia, então o diagnóstico sempre mostra algo concreto.
2. **Reunião de 20 minutos** apresentando o diagnóstico: o que aconteceu, o que é normal e o que é grave.
3. **Instalação em 5 minutos** durante a própria reunião, se o cliente aceitar.
4. **Primeiro relatório diário no dia seguinte** no WhatsApp do dono. É o momento em que o cliente percebe o valor.

## 4. Planos sugeridos

Valores iniciais para validar, ajuste depois das primeiras 10 vendas.

| Plano | Para quem | O que inclui | Preço sugerido |
|---|---|---|---|
| Diagnóstico | Qualquer empresa | Análise offline dos logs com relatório | Gratuito (isca) ou R$ 150 |
| Essencial | 1 servidor, empresa pequena | Monitoramento, alertas no WhatsApp, relatório diário sem IA | R$ 79 por servidor por mês |
| Profissional | Empresa com sistema próprio | Tudo do Essencial, relatório diário com IA, explicação de alertas críticos, ajuste mensal de regras | R$ 179 por servidor por mês |
| Gerenciado | Empresa sem ninguém de TI | Tudo do Profissional, você responde aos incidentes críticos e faz o endurecimento inicial do servidor | a partir de R$ 490 por mês |

Taxa de implantação opcional de R$ 200 a R$ 400 para o endurecimento inicial (SSH só com chave, firewall, fail2ban ou bloqueio automático).

O custo de IA por servidor é baixo porque o agente envia apenas o resumo do dia, e não os logs. Confira a tabela atual de preços da Anthropic antes de fechar a margem.

Para agências, venda por pacote: 10 servidores com desconto. Uma agência fecha vários servidores de uma vez.

## 5. Metas dos primeiros 90 dias

| Período | Meta |
|---|---|
| Semana 1 e 2 | Instalar em todos os seus servidores e da Braventon. Rodar 14 dias, ajustar regras com falso positivo real |
| Semana 3 e 4 | 5 diagnósticos gratuitos com leads e clientes atuais. 2 clientes pagantes |
| Mês 2 | 10 servidores pagantes. Coletar 2 depoimentos e 1 estudo de caso com números reais |
| Mês 3 | 20 servidores pagantes. Primeira parceria com agência ou revenda de hospedagem |

Métricas para acompanhar: servidores ativos, receita recorrente mensal, cancelamentos, alertas críticos confirmados (casos de sucesso) e taxa de falso positivo por regra.

## 6. Cuidados legais

1. **Contrato:** deixe explícito que o Atalaia é monitoramento e detecção, e não garantia de que o servidor não será invadido.
2. **LGPD:** logs contêm IPs e nomes de usuário, que são dados pessoais. Inclua no contrato que você atua como operador desses dados, com finalidade de segurança.
3. **Autorização:** só instale com autorização por escrito do responsável pelo servidor.
4. **Código:** o agente é aberto sob a licença Apache 2.0 desde a primeira versão. O que será cobrado depois é o serviço: painel central, relatórios gerenciados e resposta a incidentes (modelo open core).

## 7. Roadmap técnico

### v0.2: painel central (principal alavanca de venda)

1. Servidor central que recebe os alertas de todos os agentes via HTTPS com token por cliente.
2. Painel web com a lista de clientes, servidores, alertas e relatórios.
3. Relatório mensal em PDF por cliente, com a marca do seu negócio.
4. Alerta de agente offline (servidor parou de mandar sinal).

### v0.3: resposta ativa

1. Bloqueio automático de IP no firewall (nftables ou ufw) para força bruta e scanners, com tempo de expiração e respeito à whitelist.
2. Listas de reputação de IP gratuitas para enriquecer alertas.
3. Leitura direta do journald e dos logs de containers Docker.

### v0.4: completar a fusão com Security Onion e Wazuh

1. Leitura opcional do `eve.json` do Suricata, para clientes com servidor maior que queiram inspeção de pacotes.
2. Verificação de pacotes desatualizados com vulnerabilidades conhecidas.
3. Checklist de configuração segura (SSH, firewall, permissões), gerando uma nota de 0 a 100 por servidor.
4. Agente de IA conversacional: o cliente pergunta no WhatsApp "o que aconteceu ontem de madrugada?" e recebe a resposta.

## 8. O que NÃO fazer agora

1. Não construir o painel antes de ter 3 clientes pagando com o agente atual.
2. Não prometer "proteção total". O posicionamento é visibilidade e resposta rápida.
3. Não abrir suporte para Windows antes de dominar o mercado de VPS Linux.
