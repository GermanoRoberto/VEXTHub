# Manual Completo de Uso, Configuração e Operação — VextHub 4.0

Este manual fornece o guia passo a passo definitivo para instalação, configuração, operação diária e manutenção da plataforma **VextHub 4.0**.

---

## Sumário
1. [Filosofia do Sistema e Arquitetura Autônoma](#1-filosofia-do-sistema-e-arquitetura-autônoma)
2. [Instalação e Execução do Servidor Web](#2-instalação-e-execução-do-servidor-web)
3. [Configuração de Variáveis de Ambiente (.env)](#3-configuração-de-variáveis-de-ambiente-env)
4. [O Agente de Endpoint C# (VextHubAgent)](#4-o-agente-de-endpoint-c-vexthubagent)
5. [Guia de Operação dos Módulos do Dashboard](#5-guia-de-operação-dos-módulos-do-dashboard)
   - [5.1. Visão Geral da Frota](#51-visão-geral-da-frota)
   - [5.2. Gestão de Dispositivos e Aba V-Recon (TVM)](#52-gestão-de-dispositivos-e-aba-v-recon-tvm)
   - [5.3. Painel de Segurança em Tempo Real & Combinações Tóxicas](#53-painel-de-segurança-em-tempo-real--combinações-tóxicas)
   - [5.4. Postura Zero Trust & Radar de Shadow IT](#54-postura-zero-trust--radar-de-shadow-it)
   - [5.5. Fast-Track de Incidentes, SLAs e Raio de Explosão](#55-fast-track-de-incidentes-slas-e-raio-de-explosão)
   - [5.6. Gestão de Conformidade e Exportação de Relatórios (PDF/CSV)](#56-gestão-de-conformidade-e-exportação-de-relatórios-pdfcsv)
   - [5.7. Laboratório Forense de Malware](#57-laboratório-forense-de-malware)
   - [5.8. Diagnóstico de Infraestrutura e Serviços](#58-diagnóstico-de-infraestrutura-e-serviços)
6. [Integração do Threat Feed com Firewalls de Borda](#6-integração-do-threat-feed-com-firewalls-de-borda)
7. [Subindo o Projeto com Segurança para o GitHub Privado](#7-subindo-o-projeto-com-segurança-para-o-github-privado)

---

## 1. Filosofia do Sistema e Arquitetura Autônoma

O VextHub foi concebido sob a premissa fundamental de **Custo Zero e Dependência Zero de Sistemas Proprietários Pagos**:
- **Sem assinaturas comerciais**: Você não precisa pagar por licenças recorrentes ou plataformas corporativas proprietárias.
- **Sem consumo de APIs pagas por consulta**: Os comparadores de versões de software, as regras de caminhos de ataque, os cálculos de postura e o catálogo de vulnerabilidades funcionam **100% no servidor local**.
- **Independência de Nuvem Externa**: A plataforma pode rodar totalmente em rede local (*on-premises*), em um servidor próprio ou em qualquer VPS de baixo custo.

---

## 2. Instalação e Execução do Servidor Web

### Pré-requisitos
- **Node.js**: Versão 20.x ou superior (LTS recomendada).
- **Gerenciador de Pacotes**: `npm` (incluso no Node.js).
- **Sistema Operacional**: Windows, Linux ou macOS.

### Passo 1: Instalar Dependências
No diretório raiz do projeto, execute:
```powershell
npm install
```

### Passo 2: Inicializar o Servidor em Desenvolvimento
```powershell
npm run dev
```
O servidor estará disponível no endereço: **`http://localhost:3000`**

### Passo 3: Inicialização Rápida no Windows (Script Pronto)
Para facilitar o início do dia a dia no Windows, você pode simplesmente dar dois cliques no arquivo:
```powershell
abrir_servidor.bat
```
ou via PowerShell:
```powershell
.\dev.ps1
```

### Passo 4: Compilação de Produção
Para gerar a versão otimizada de produção e verificar se há qualquer inconsistência:
```powershell
npm run build
```
Para rodar a versão de produção compilada:
```powershell
npm run start
```

---

## 3. Configuração de Variáveis de Ambiente (.env)

O arquivo de variáveis de ambiente deve ficar na raiz do projeto com o nome `.env`. Use o `.env.example` como modelo:

```powershell
copy .env.example .env
```

### Variáveis Principais e Suas Funções:

```env
# ==========================================
# 1. SEGURANÇA E COMUNICAÇÃO DO AGENTE (OBRIGATÓRIO)
# ==========================================
# Chave compartilhada usada para autenticação de telemetria e geração de pacotes.
# Deve ter NO MÍNIMO 24 caracteres aleatórios (recomenda-se 32+).
AGENT_SHARED_SECRET=sua_chave_secreta_super_forte_gerada_aleatoriamente_123456

# ==========================================
# 2. BANCO DE DADOS SUPABASE / POSTGRESQL (OPCIONAL)
# ==========================================
# Caso você use o Supabase gerenciado ou PostgreSQL próprio:
NEXT_PUBLIC_SUPABASE_URL=https://seu-projeto.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sua_anon_public_key
SUPABASE_SERVICE_ROLE_KEY=sua_service_role_key

# Se você NÃO configurar as variáveis do Supabase, o sistema entra
# AUTOMATICAMENTE no "Modo Local Standalone", operando com o estado
# em memória e arquivo JSON (scripts/simulation_state.json), ideal para testes.

# ==========================================
# 3. BACKEND TÁTICO FASTAPI / REDIS (OPCIONAL)
# ==========================================
# Usado caso suba os containers adicionais em infra/docker-compose.yml:
DATABASE_URL=postgresql://vexthub:vexthub@localhost:5432/vexthub
REDIS_URL=redis://localhost:6379/0
API_INTERNAL_TOKEN=seu_token_interno_api
```

---

## 4. O Agente de Endpoint C# (VextHubAgent)

O agente de coleta de dados do VextHub é um binário nativo em C# (.NET Framework 4.0), extremamente leve (~40 KB) e que consome menos de 15 MB de memória RAM.

### Requisitos do Cliente
- Windows 7, 8.1, 10, 11 ou Windows Server (2012 R2 até 2025).
- .NET Framework 4.0 ou superior (já vem pré-instalado nativamente em qualquer Windows moderno).

### Como Compilar o Agente
Se você fizer alterações no código do agente (`src/installer/VextHubAgent.cs`), recompile os executáveis com o script PowerShell:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File src/installer/build_installer.ps1
```
Esse script utiliza o compilador nativo do Windows (`csc.exe`) e gera:
- `public/installer/VextHubAgent.exe`
- `public/installer/VextHub_Agent.exe`

### Modos de Execução do Agente

#### Modo 1: Bandeja do Sistema (Tray - Modo Usuário)
Basta colocar o `VextHubAgent.exe` e o `config.json` em uma pasta e executar o `VextHubAgent.exe`.
- Um ícone com o logo do VextHub aparecerá perto do relógio do Windows.
- O agente coleta a telemetria a cada 10 minutos e envia via HTTPS para o servidor.
- O usuário pode clicar com o botão direito para ver o status ou forçar um pulso imediato.

#### Modo 2: Serviço do Windows (Windows Service - Recomendado para Empresas)
Para que o agente inicie automaticamente mesmo sem nenhum usuário logado na máquina:
1. Abra o **PowerShell como Administrador** na pasta onde está o agente.
2. Registre o serviço no Windows:
   ```powershell
   .\VextHubAgent.exe --install-service
   ```
3. Inicie o serviço:
   ```powershell
   Start-Service VextHubAgent
   ```
4. Para remover o serviço futuramente:
   ```powershell
   Stop-Service VextHubAgent
   .\VextHubAgent.exe --uninstall-service
   ```

### Formato do Arquivo `config.json`
O executável busca o arquivo `config.json` no mesmo diretório:
```json
{
  "server_url": "http://SEU_IP_OU_DOMINIO:3000",
  "unit_name": "Matriz",
  "agent_key": "sua_chave_secreta_configurada_no_env",
  "interval_seconds": 600
}
```

---

## 5. Guia de Operação dos Módulos do Dashboard

Acesse o painel no navegador em: `http://localhost:3000/dashboard`

### 5.1. Visão Geral da Frota (`/dashboard`)
- **Cards Superiores**: Exibição da quantidade total de máquinas cadastradas, máquinas online (com pulso recente), dispositivos em quarentena e vulnerabilidades críticas ativas.
- **Gráfico de Postura Global**: Divisão percentual da frota entre `TRUSTED`, `RESTRICTED` e `QUARANTINED`.
- **Atividades Recentes**: Registro em tempo real de novos alertas, alterações de conformidade e comandos emitidos.

---

### 5.2. Gestão de Dispositivos e Aba V-Recon (TVM) (`/dashboard/machines`)
Ao clicar em qualquer máquina da lista, abre-se o painel lateral com as abas de diagnóstico:
- **Aba Geral / Hardware**: Fabricante, modelo, número de série, CPU, RAM, uso de disco e endereço IP.
- **Aba Softwares**: Lista completa de programas instalados com suas respectivas versões identificadas no Registro do Windows.
- **Aba Processos**: Processos ativos em execução no momento do último pulso.
- **Aba Portas de Rede**: Portas TCP em escuta e conexões estabelecidas.
- **Aba Reconhecimento (V-Recon — Gestão de Vulnerabilidades)**:
  - **Escore de Risco do Host**: Pontuação de 0 a 100 baseada na gravidade dos achados.
  - **Cards de CVEs Identificadas**: Softwares com versões desatualizadas que possuem falhas conhecidas.
  - **Badge CISA KEV**: Destaque em vermelho vivo para vulnerabilidades ativamente exploradas no mundo real (como as brechas históricas do WinRAR, OpenSSH regreSSHion, 7-Zip, etc.).
  - **Escore CVSS v3**: Gravidade matemática da vulnerabilidade (Ex: 9.8 Crítica).
  - **Recomendação de Correção**: Versão exata para a qual o software deve ser atualizado.

---

### 5.3. Painel de Segurança em Tempo Real & Combinações Tóxicas (`/dashboard/security`)
O motor correlaciona múltiplos eventos para detectar ataques complexos antes que o dano se propague:

#### Caminhos de Ataque Monitorados:
1. **Brecha Remota (*Remote Breach Path*)**:
   - Detecta quando uma máquina possui um software com CVE Crítica ou ferramenta de acesso remoto não autorizada **combinada** com uma porta sensível em escuta (RDP 3389, SMB 445, VNC 5900 ou SSH 22) e uma conexão externa ativa.
2. **Persistência Oculta (*Stealth Persistence Path*)**:
   - Detecta binários rodando a partir de diretórios temporários (`%TEMP%` ou `%APPDATA%`) associados a entradas no Registro de Inicialização do Windows e uso de LOLBins codificados (ex: PowerShell com `-encodedCommand`).
3. **Movimentação Lateral & Roubo de Credenciais (*Lateral Movement Path*)**:
   - Detecta acessos suspeitos à memória do processo `lsass.exe` ou dump de credenciais associado a sessões externas de SMB/RDP e anomalias de hardware com desvio padrão populacional (Z-Score $\ge 2.5$).

---

### 5.4. Postura Zero Trust & Radar de Shadow IT
No topo da página de Segurança, você visualiza o veredito contínuo de cada endpoint:
- **`TRUSTED` (Verde)**: Dispositivo íntegro, sem CVEs críticas, sem portas sensíveis expostas e com software autorizado.
- **`RESTRICTED` (Amarelo)**: Dispositivo com avisos moderados, portas expostas ou softwares desatualizados sem exploração crítica.
- **`QUARANTINED` (Vermelho)**: Dispositivo comprometido por um caminho de ataque ativo ou usando ferramentas de túnel não homologadas.

#### Radar de Túneis Reversos (Shadow IT):
O agente e o servidor monitoram processos e conexões para flagrar tentativas de burlar o firewall da empresa:
- Identifica ferramentas como **`ngrok`**, **`cloudflared`**, **`tailscale`**, **`zerotier`**, **`chisel`**, **`tor`**, **`plink`**, além de portas C2 clássicas (`4444`, `1337`, `3333`, `8443`).

---

### 5.5. Fast-Track de Incidentes, SLAs e Raio de Explosão
No painel de Segurança, cada incidente passa por uma esteira operacional estruturada:
- **Fases do Incidente**: `TRIAGE` (Triagem) $\rightarrow$ `CONTAINMENT` (Contenção) $\rightarrow$ `ERADICATION` (Erradicação) $\rightarrow$ `RECOVERED` (Recuperado).
- **Controle de SLA em Tempo Real**:
  - Severidade Crítica: **1 hora**
  - Severidade Alta: **4 horas**
  - Severidade Média: **24 horas**
  - Severidade Baixa: **72 horas**
- **Cálculo de Raio de Explosão (*Blast Radius*)**:
  - Ao inspecionar um alerta, o sistema mostra um badge indicando quantas outras máquinas da sua rede compartilham a mesma vulnerabilidade ou porta aberta. Clicando no badge, você obtém a lista imediata dos hosts expostos.
- **Métricas de SOC**: Acompanhamento dos tempos médios de resposta:
  - **MTTD** (*Mean Time to Detect*): Tempo médio até o sistema registrar o incidente.
  - **MTTR** (*Mean Time to Remediate*): Tempo médio até a conclusão da contenção.

---

### 5.6. Gestão de Conformidade e Exportação de Relatórios (`/dashboard/compliance`)
- **Regras por Unidade**: Configure políticas de software por filial ou departamento (softwares obrigatórios vs. softwares proibidos).
- **Exportação de Laudos em PDF Executivo**:
  - Gera um laudo em formato PDF vetorial estruturado com cabeçalho corporativo, métricas de risco, tabela de conformidade, inventário de CVEs e cobertura das normas **ISO/IEC 27001:2022** e **LGPD**.
- **Exportação em CSV**:
  - Exporta tabelas completas compatíveis com Microsoft Excel e PowerBI (formato RFC-4180 com codificação UTF-8 BOM para evitar problemas com acentuação).

---

### 5.7. Laboratório Forense de Malware (`/dashboard/forensics`)
Permite submeter arquivos suspeitos para inspeção estática determinística imediata:
- **Cálculo de Hash SHA-256**: Identificação única do binário.
- **Entropia de Shannon**: Mede o nível de aleatoriedade dos bytes para indicar se o arquivo está empacotado (*packed*), ofuscado ou criptografado.
- **Inspeção de Cabeçalhos PE**: Análise de seções executáveis do Windows (ex: `.text`, `.data`, `.rsrc`), imports de APIs suspeitas da API Win32 e verificação de assinatura digital.

---

### 5.8. Diagnóstico de Infraestrutura e Serviços (`/dashboard/settings`)
Na aba de configurações, você tem um painel de diagnóstico em tempo real que afere a saúde e a latência (em milissegundos) dos componentes do VextHub:
- Status da base de dados (PostgreSQL/Supabase vs. Modo Local).
- Status do Backend Tático FastAPI.
- Status do Barramento de Mensagens / Fila Redis.
- Modo de Autenticação Ativo.
- Botão "Testar Conectividade" para revalidar tudo com um clique.

---

## 6. Integração do Threat Feed com Firewalls de Borda

O VextHub possui uma API pronta para alimentar firewalls e roteadores corporativos para isolamento automático de máquinas infectadas ou em quarentena:

**Endpoint Protegido**: `/api/security/zerotrust-feed`

### Autenticação:
Passe a chave configurada no `.env` via cabeçalho `x-agent-secret`:
```http
GET /api/security/zerotrust-feed?format=pfsense HTTP/1.1
Host: seu-servidor-vexthub:3000
x-agent-secret: seu_agent_shared_secret
```

### Formatos Suportados:
| Parâmetro `format` | Firewall / Sistema Destino | Formato da Resposta |
|---|---|---|
| `?format=pfsense` ou `?format=plain` | **pfSense / OPNsense** | Lista de IPs em texto puro (um por linha), ideal para URL Table Aliases. |
| `?format=fortigate` | **Fortinet FortiGate** | Formato de Threat Feed externo compatível com Fabric Connectors. |
| `?format=mikrotik` | **MikroTik RouterOS** | Comandos de script no formato `/ip firewall address-list add list=VextHub_Blocklist address=...` |
| `?format=iptables` | **Linux (iptables / ipset)** | Formato de script para carga direta via `ipset restore`. |
| `?format=json` (Padrão) | Qualquer sistema via API | JSON estruturado com IP, hostname, severidade, razão do bloqueio e timestamp. |

---

## 7. Subindo o Projeto com Segurança para o GitHub Privado

Para subir o código para o seu repositório pessoal ou corporativo garantindo que **nenhum segredo, senha ou arquivo desnecessário seja exposto**, siga este procedimento seguro:

### Passo 1: Verificar se os Segredos estão Protegidos
O arquivo `.gitignore` do VextHub já vem configurado para **bloquear** o commit de:
- Arquivos `.env`, `.env.local`, `.env.production`
- Pastas de bibliotecas (`node_modules/`, `__pycache__/`)
- Logs de depuração e caches de agentes (`.agents/`, `scratch/`)
- Pastas de compilação (`.next/`, `build/`, `dist/`)

Para ter certeza de que o seu `.env` com senhas não será commitado, execute:
```powershell
git status --ignored
```
*(O arquivo `.env` deve aparecer na lista de ignorados).*

### Passo 2: Inicializar o Repositório Git (Caso ainda não esteja inicializado)
```powershell
git init
```

### Passo 3: Adicionar os Arquivos e Fazer o Primeiro Commit
```powershell
git add .
git commit -m "feat: release do VextHub 4.0 - plataforma completa de gestao e ciberdefesa"
```

### Passo 4: Criar o Repositório no GitHub
1. Acesse o [GitHub](https://github.com/new).
2. Dê um nome ao repositório (ex: `vexthub-enterprise`).
3. **MUITO IMPORTANTE**: Marque a opção **Private** (Privado) para que o código não fique público na internet.
4. Clique em **Create repository**.

### Passo 5: Vincular e Enviar o Código
Copie a URL do seu repositório criado e rode no seu terminal:
```powershell
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
git push -u origin main
```

---

## Conclusão e Próximos Passos

O **VextHub 4.0** está completamente estruturado, documentado e homologado para uso corporativo com custo zero.

Com esta base sólida, a plataforma está pronta para receber a extensão de **Monitoramento Ativo via Zabbix**, onde os dados de rede coletados pelo Zabbix serão cruzados diretamente com os motores de postura e vulnerabilidades documentados neste manual.
