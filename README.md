# Egogero Condominium

Sistema multi-condominio para controle de acesso de pedestres e veiculos por convites temporarios de uso unico. A aplicacao separa operacoes de provedor, sindico, morador e portaria com autorizacao por papel e por condominio.

> O projeto esta em desenvolvimento. O laboratorio local descrito abaixo e sintetico e nao representa homologacao, canario ou evidencia de producao.

## Capacidades

- cadastro e desativacao logica de condominios, moradores e convidados;
- convites individuais ou em lote com codigo numerico de seis digitos, expiracao, revogacao e consumo atomico;
- limites diarios por condominio e por morador, respeitando o fuso horario local;
- validacao na portaria por dispositivo provisionado ou sessao humana;
- RBAC multi-tenant para `provedor`, `sindico`, `morador` e `portaria`;
- autenticacao humana OIDC com Authorization Code + PKCE, sessao segura, CSRF, MFA por papel e reautenticacao;
- idempotencia transacional, outbox, workers de entrega e revogacao por recuperacao;
- auditoria imutavel, minimizacao de dados, retencao e anonimizacao;
- rollout gradual da autenticacao humana com telemetria e alertas limitados;
- interface React responsiva e API Fastify sobre PostgreSQL.

## Arquitetura

```text
Navegador
   |
HTTPS / OIDC
   |
Fastify + React  --------  Provedor OIDC
   |
PostgreSQL
   |-- worker de entrega de convites
   |-- worker de revogacao por recuperacao
   `-- jobs de retencao e limpeza

Prometheus  <--  Blackbox Exporter / PostgreSQL Exporter  -->  Grafana
```

Tecnologias principais:

- Node.js 22, TypeScript e Fastify;
- React 19 e Vite;
- PostgreSQL 16, Prisma e migracoes SQL versionadas;
- Keycloak e Caddy no laboratorio OIDC local;
- Prometheus, Blackbox Exporter, PostgreSQL Exporter e Grafana;
- Node Test Runner, Vitest e Playwright.

## Inicio rapido

O caminho recomendado para avaliar o sistema completo e o laboratorio local gratuito. Ele inclui PostgreSQL, HTTPS, Keycloak, aplicacao, workers e observabilidade.

### Requisitos

- Docker Engine com o plugin Docker Compose;
- Node.js 22 e npm;
- capacidade local para executar dois PostgreSQL, Keycloak e os servicos de aplicacao e observabilidade;
- resolucao de `*.localhost` para loopback, suportada normalmente por navegadores e resolvers modernos.

### Subir e validar

```sh
npm ci
npm run local-staging:up
npm run local-staging:check
npm run local-staging:login-check
npm run local-staging:credentials
```

Servicos disponiveis:

| Servico | Endereco |
| --- | --- |
| Aplicacao | `https://office.localhost:8443` |
| Administracao do Keycloak | `https://auth.localhost:8443/admin` |
| Prometheus | `http://127.0.0.1:9090` |
| Grafana | `http://127.0.0.1:3002` |

As credenciais sao geradas em `.local-staging/`, com permissao `0600`, e nao entram no Git nem no contexto de build. Para teste manual, importe `.local-staging/caddy-root.crt` somente em um perfil descartavel do navegador.

Ao terminar:

```sh
npm run local-staging:down
```

Esse comando preserva credenciais e volumes. Para remover todo o estado local:

```sh
npm run local-staging:reset
```

Consulte [Laboratorio local sintetico](docs/local-staging-lab.md) para operacao, limites e diagnostico.

## Desenvolvimento

Para trabalhar apenas com a API e PostgreSQL, use a autenticacao por cabecalhos exclusiva de desenvolvimento:

```sh
npm ci
docker compose up -d db
DATABASE_URL=postgresql://office:office@127.0.0.1:5432/office npm run db:migrate:deploy
docker compose up --build app
```

A API fica em `http://127.0.0.1:3001`. O `docker-compose.yml` usa segredos locais conhecidos e `LOCAL_DEVELOPMENT_AUTH=true`; nunca reutilize essa configuracao em staging ou producao.

Os cabecalhos de desenvolvimento sao:

```http
X-Development-User-Id: provider-1
X-Development-User-Role: provedor
X-Development-Condominio-Id: *
```

Para papeis vinculados a um tenant, substitua `*` pelo UUID do condominio. Esses cabecalhos sao recusados em ambientes implantados.

Depois de alteracoes no backend ou frontend, reconstrua o servico para que o Fastify sirva os artefatos atualizados:

```sh
docker compose up --build app
```

## Qualidade

Execute a verificacao completa antes de enviar alteracoes:

```sh
npm run lint
npm run typecheck
npm test
npm run build
```

Testes que dependem de PostgreSQL real exigem uma base descartavel e as variaveis indicadas pelos proprios testes. A suite de navegador aceita somente a base local isolada abaixo e pode cria-la quando o usuario `office` tem permissao:

```sh
docker compose up -d db
export DATABASE_URL='postgresql://office:office@127.0.0.1:5432/office_pc31_e2e?schema=public'
npm run test:e2e:install
npm run test:e2e
```

## Estrutura do repositorio

| Caminho | Responsabilidade |
| --- | --- |
| `src/` | API, autenticacao, autorizacao, dominio e workers |
| `web/` | interface React e sistema visual da aplicacao |
| `prisma/` | schema e migracoes PostgreSQL |
| `test/` | testes unitarios, de integracao e contratos de seguranca |
| `deploy/` | inventario de ambiente e configuracao do laboratorio local |
| `scripts/` | verificacoes, rehearsals e automacao operacional |
| `docs/` | contratos de arquitetura, seguranca, rollout e operacao |

## Seguranca e implantacao

- nunca versione `.env`, `.local-staging/`, credenciais, tokens ou certificados privados;
- staging e producao exigem HTTPS terminado por proxy confiavel e `TRUST_PROXY` restrito aos hops reais;
- autenticacao humana implantada exige OIDC, PKCE, sessao, MFA, recuperacao e rollout configurados de forma completa;
- migracoes devem rodar em job separado antes da aplicacao;
- o container de runtime opera como usuario `node` e deve usar filesystem raiz somente leitura;
- os resultados do laboratorio local nao substituem secret manager, alertas externos, MFA real, telemetria independente ou uma janela canario observada.

Leia [Contrato de implantacao](docs/deployment-contract.md), [Rollout de autenticacao humana](docs/human-auth-rollout.md) e [Observabilidade de autenticacao](docs/auth-observability.md) antes de preparar um ambiente implantado.

## Documentacao

- [Laboratorio local sintetico](docs/local-staging-lab.md)
- [Contrato de implantacao](docs/deployment-contract.md)
- [Provisionamento, MFA e recuperacao](docs/human-provisioning-mfa-recovery.md)
- [Rollout de autenticacao humana](docs/human-auth-rollout.md)
- [Readiness do rollout](docs/human-auth-rollout-readiness.md)
- [Observabilidade de autenticacao](docs/auth-observability.md)
- [Contrato de links de convite](docs/invitation-link-contract.md)
- [Idempotencia e outbox](docs/invitation-idempotency-outbox.md)
- [Worker de entrega](docs/invitation-delivery-worker.md)
- [Retencao de dados](docs/data-retention.md)
- [Seguranca E2E no navegador](docs/e2e-browser-security.md)
