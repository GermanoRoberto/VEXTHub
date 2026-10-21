@echo off
title VextHub Launcher
cd /d %~dp0

echo ==========================================
echo       INICIANDO VEXTHUB (FRONT + API)
echo ==========================================

:: 1. Verificar se npm ja esta no PATH
where npm >nul 2>nul
if %errorlevel% equ 0 goto node_ok

:: 2. Se nao estiver, verificar se esta instalado nos locais padrao
if exist "C:\Program Files\nodejs\node.exe" set "PATH=%PATH%;C:\Program Files\nodejs"
if exist "C:\Program Files\nodejs\node.exe" goto node_check_after_path

if exist "C:\Program Files (x86)\nodejs\node.exe" set "PATH=%PATH%;C:\Program Files (x86)\nodejs"
if exist "C:\Program Files (x86)\nodejs\node.exe" goto node_check_after_path

:node_check_after_path
where npm >nul 2>nul
if %errorlevel% equ 0 goto node_ok

:: 3. Se ainda nao encontrado, instalar com winget
echo [INFO] Node.js/npm nao foi detectado no sistema.
echo [INFO] Tentando instalar o Node.js automaticamente com o winget...

winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements

:: Tenta atualizar o PATH apos a instalacao
if exist "C:\Program Files\nodejs\node.exe" set "PATH=%PATH%;C:\Program Files\nodejs"
if exist "C:\Program Files (x86)\nodejs\node.exe" set "PATH=%PATH%;C:\Program Files (x86)\nodejs"

where npm >nul 2>nul
if %errorlevel% equ 0 (
    echo [SUCESSO] Node.js instalado e configurado na sessao atual!
    goto node_ok
)

echo [ERRO] Falha ao instalar o Node.js automaticamente.
echo [DICA] Por favor, instale o Node.js manualmente em: https://nodejs.org/
pause
exit /b

:node_ok

:: 2. Instalar dependencias do Node (npm install) se a pasta node_modules nao existir
if not exist node_modules (
    echo [INFO] node_modules nao encontrado. Instalando dependencias do frontend - isso pode demorar um pouco...
    cmd /c npm install
)

:: 3. Instalar dependencias do Python (pip install)
echo [INFO] Garantindo dependencias do Backend Python (FastAPI)...
python -m pip install -r services/api/requirements.txt

echo.
echo ==========================================
echo       INICIANDO SERVICOS...
echo ==========================================

echo [1/3] Abrindo Backend Python (FastAPI)...
:: Adicionado -ExecutionPolicy Bypass para evitar erro de scripts desabilitados no PowerShell
start powershell -ExecutionPolicy Bypass -NoExit -Command "echo '--- BACKEND LOGS ---'; npm run api:dev"

echo [2/3] Iniciando Simulador de Escala (2.7k Agentes)...
start powershell -ExecutionPolicy Bypass -NoExit -Command "echo '--- SIMULADOR DE TELEMETRIA ---'; python -u scripts/telemetry_simulator.py --ticks 9999999"

echo [3/3] Iniciando Frontend Next.js...
:: Usando cmd /c para garantir que o npm seja chamado corretamente no Windows
cmd /c npm run dev

pause

