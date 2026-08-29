# Kit de referência de design REV. 07

Referências estáticas para alinhar produto, design e engenharia no sistema de controle de acesso a condomínios. Abra `index.html` diretamente no navegador para navegar pelo catálogo. Estas páginas não são a aplicação de produção, não executam fluxos e não definem contratos de API, autorização ou segurança.

## Fonte

Derivado da entrega local `/home/teagar/Downloads/teagar-company-sistema-de-design(7).html`, recebida em 29 de agosto de 2026 e identificada neste projeto como **Teagar REV. 07** pelo sufixo `(7)`. O documento recebido ainda se identifica internamente como `REV. 03` e `Versão 01.0`; essa divergência é preservada na proveniência, sem inventar uma revisão que o arquivo não declara.

A atribuição, o hash e a decisão de não duplicar imagens base64 estão em `source/README.md`.

## Arquitetura da informação

- `index.html`: catálogo e princípios.
- `foundations.html`: paleta, tipografia, escala, estados e regras anti-slop da entrega REV. 07.
- `auth/`: entrada OIDC, convite administrativo, segurança e encerramento de sessão.
- `shell/`: envelope autenticado e seleção explícita de condomínio/papel.
- `roles/`: painéis de provedor, síndico, morador e portaria.
- `styles/`: tokens derivados e componentes/layouts compartilhados.
- `assets/`: marca SVG compacta.

## Regras de design

- Charcoal e paper estruturam superfícies; laranja signal indica decisão; azul blueprint orienta navegação e contexto.
- Espaçamento usa `--s-1` a `--s-8`, sempre em múltiplos de 8 px. Cantos permanecem técnicos em `--r-sm` (2 px) e `--r-md` (4 px).
- Big Shoulders Display é editorial, Public Sans é texto/interface e IBM Plex Mono é metadado/status.
- A escala tipográfica recebida usa 8, 13, 21, 34, 55, 89 e 144 px. No produto, tamanhos responsivos podem usar `clamp()` sem perder esses degraus como referências de hierarquia.
- As referências carregam Google Fonts para conveniência. Produção deve auto-hospedar arquivos versionados, com fallback e política de privacidade adequada.
- Sem gradientes decorativos. O único gradiente é funcional, no estado skeleton de carregamento.
- Evitar cartões dentro de cartões: borda e agrupamento existem somente quando definem uma unidade operacional.
- Ícones usam SVG inline com `currentColor`, traço quadrado e classe `.icon`; nunca emoji.
- Uma cor semântica só aparece quando representa um estado real. Não use badges para ornamentação.
- Marcas de registro e grid blueprint são recursos pontuais de contexto técnico, não fundos automáticos de toda superfície.

## Regras anti-slop

- Não usar gradientes roxo/índigo, glassmorphism, glow ou paletas néon concorrentes.
- Não usar Inter, Roboto, Arial ou Space Grotesk como tipografia do produto.
- Não usar emojis em navegação, botões ou títulos estruturais.
- Não usar cartões aninhados, sombras em camadas ou bordas redundantes.
- Não usar botão-pílula, raio fora de 2–4 px ou espaçamento fora da grade de 8 px.
- Não usar texto de baixo contraste, status decorativo ou copy promocional vaga.
- Preferir uma superfície neutra dominante; signal é reservado para a decisão ou alerta prioritário.

## Responsividade

- Desktop: acima de 900 px, com navegação lateral no shell.
- Tablet: 641 a 900 px, grids reduzidos e navegação inferior no shell.
- Mobile: até 640 px, coluna única e tabelas transformadas em registros rotulados.
- Conteúdo tabular largo pode usar `.table-wrap`, sem ampliar o viewport da página.
- A barra inferior oferece os mesmos destinos da navegação lateral. Nenhum destino desaparece silenciosamente.

## Acessibilidade e segurança

- Alvos interativos têm no mínimo 44 px, foco visível e movimento reduzido respeitado.
- Landmarks, títulos, captions, labels e mensagens de estado não dependem apenas de cor.
- Erros de autenticação e acesso são genéricos; nenhum token sensível aparece na interface.
- Login é exclusivamente OIDC, sem senha local. Recuperação pertence ao provedor de identidade.
- Convites de provisionamento humano expiram em 24 horas. Convites de acesso de visitante são outro domínio e usam código de seis dígitos.
- Contexto de condomínio e papel é sempre explícito. CSRF, credenciais e sessões não são representados como armazenamento do navegador.

## Decisões de derivação

- O exemplo da fonte usa 48 horas para convite administrativo; o kit mantém 24 horas porque esse é o contrato vigente do Egogero. O HTML é autoridade visual, não funcional.
- O exemplo de shell da fonte contém um emoji de edifício, em conflito com as próprias regras anti-slop. O kit usa SVG com `currentColor`.
- O exemplo de morador da fonte trata convite de vínculo. O kit separa provisionamento humano de código de visitante de seis dígitos, conforme o domínio implementado.
- A entrega `(7)` demonstra tema escuro no documento-guia, mas o seletor demonstrativo não persiste preferência nem inicializa pela preferência do sistema. Este kit permanece intencionalmente claro: um tema só deve entrar quando todas as superfícies, persistência, preferência do sistema e regressão visual forem implementadas juntas.
- A marca compacta local é uma interpretação vetorial sem payload raster; não é uma extração das imagens incorporadas na fonte.

## Uso

Use as páginas para revisão visual, prototipação e critérios de aceite. Ao implementar, conecte componentes reais, estados autorizados no servidor, conteúdo validado e telemetria apropriada; não copie ações estáticas como comportamento funcional.
