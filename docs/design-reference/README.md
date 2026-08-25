# Kit de referência de design

Referências estáticas para alinhar produto, design e engenharia no sistema de controle de acesso a condomínios. Abra `index.html` diretamente no navegador para navegar pelo catálogo. Estas páginas não são aplicação de produção, não executam fluxos e não definem contratos de API.

## Fonte

Derivado do arquivo `teagar-company-sistema-de-design(1).html` fornecido em 24 de agosto de 2026. A atribuição e a decisão de não duplicar as imagens base64 estão em `source/README.md`.

## Arquitetura da informação

- `index.html`: catálogo e princípios.
- `auth/`: entrada OIDC, convite administrativo, segurança e encerramento de sessão.
- `shell/`: envelope autenticado e seleção explícita de condomínio/papel.
- `roles/`: painéis de provedor, síndico, morador e portaria.
- `styles/`: tokens imutáveis e componentes/layouts compartilhados.
- `assets/`: marca SVG compacta.

## Regras de design

- Charcoal e paper estruturam superfícies; laranja signal indica decisão; azul blueprint orienta navegação e contexto.
- Espaçamento segue múltiplos de 8 px. Cantos permanecem técnicos, entre 2 e 4 px.
- Big Shoulders Display é editorial, Public Sans é texto/interface e IBM Plex Mono é metadado/status.
- As referências carregam Google Fonts para conveniência. Produção deve auto-hospedar arquivos versionados, com fallback e política de privacidade adequada.
- Sem gradientes decorativos. O único gradiente é funcional, no estado skeleton de carregamento.
- Evitar cartões dentro de cartões: borda e agrupamento existem somente quando definem uma unidade operacional.
- Ícones usam SVG inline com `currentColor`, traço quadrado e classe `.icon`; nunca emoji.

## Responsividade

- Desktop: acima de 900 px, com navegação lateral no shell.
- Tablet: 641 a 900 px, grids reduzidos e navegação inferior no shell.
- Mobile: até 640 px, coluna única e tabelas transformadas em registros rotulados.
- Conteúdo tabular largo pode usar `.table-wrap`, sem ampliar o viewport da página.

## Acessibilidade e segurança

- Alvos interativos têm no mínimo 44 px, foco visível e movimento reduzido respeitado.
- Landmarks, títulos, captions, labels e mensagens de estado não dependem apenas de cor.
- Erros de autenticação e acesso são genéricos; nenhum token sensível aparece na interface.
- Login é exclusivamente OIDC, sem senha local. Recuperação pertence ao provedor de identidade.
- Convites de provisionamento humano expiram em 24 horas. Convites de acesso de visitante são outro domínio e usam código de seis dígitos.
- Contexto de condomínio e papel é sempre explícito. CSRF, credenciais e sessões não são representados como armazenamento do navegador.

## Uso

Use as páginas para revisão visual, prototipação e critérios de aceite. Ao implementar, conecte componentes reais, estados autorizados no servidor, conteúdo validado e telemetria apropriada; não copie ações estáticas como comportamento funcional.
