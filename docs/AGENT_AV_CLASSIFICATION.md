# VextHub Agent - AV/EDR classification checklist

Este documento separa assinatura de codigo, reputacao e comportamento. Um certificado ajuda o Windows, SmartScreen e consoles de seguranca a reconhecerem o publisher, mas nao autoriza comportamento com cara de evasao.

## O que estava com maior risco

| Sinal | Onde apareceu | Classificacao provavel | Resolvido por certificado? | Acao |
| --- | --- | --- | --- | --- |
| `ExecutionPolicy Bypass` | launcher PowerShell legado | script policy bypass / PUA | Parcial | Removido do launcher de instalacao |
| Ofuscacao de strings/WMI/API | agente C# | obfuscation / trojan-like static trait | Nao | Fluxo do agente deve manter strings legiveis |
| Anti-sandbox e sleep longo aleatorio | agente C# | anti-analysis / evasive behavior | Nao | Removido do caminho ativo |
| User-Agent fingindo navegador | agente C# | network masquerading / C2-like | Nao | Agente usa `VextHubAgent/<versao>` |
| Arquivo oculto/sistema | agente C# | file concealment | Nao | Inicializacao passa a usar nome real do produto |
| Nome parecido com Windows Update + `.url` no Startup | agente C# | masqueraded persistence | Nao | Inicializacao passa a usar `HKCU\...\Run` com `VextHubEndpointAgent` |

## Sinais que ainda exigem revisao

| Sinal | Justificativa | Mitigacao esperada |
| --- | --- | --- |
| Canal de comandos remotos | E normal para RMM/EDR, mas e dual-use | allowlist fechada, comandos assinados, auditoria, tenant binding |
| Scheduled Task no instalador PowerShell legado | Persistencia legitima, mas comum em malware | tratar como fallback legado; caminho recomendado e o agente C# assinado |

## Como validar antes da certificacao

1. Rodar `npm run sim:agent-install:classification`.
2. Abrir `http://localhost:3000/agent_install_log.html`.
3. Verificar a secao `Deteccao AV/EDR`.
4. Corrigir todo item `high` ou `critical` antes de submeter para certificado/allowlist.
5. Submeter o binario assinado para o portal do fornecedor de seguranca junto com descricao funcional, hash SHA-256, dominio de comunicacao e politica de comandos.

## O que nao fazer em producao

- Nao desativar antivirus localmente.
- Nao tentar alterar Tamper Protection.
- Nao usar nomes de sistema operacional para esconder o agente.
- Nao usar `ExecutionPolicy Bypass` como caminho normal de instalacao.
- Nao ocultar binarios do produto.
