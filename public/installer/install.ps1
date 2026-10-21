[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$UnitName,
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

$CurrentDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($CurrentDir)) { $CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrEmpty($CurrentDir)) { $CurrentDir = Get-Location }

$InstallPath = Join-Path $env:LOCALAPPDATA "VextHub\AgentLegacy"
$AgentFile = Join-Path $InstallPath "agent.ps1"
$ConfigFile = Join-Path $InstallPath "config.json"
$SourceAgent = Join-Path $CurrentDir "agent.ps1"
$SourceConfig = Join-Path $CurrentDir "config.json"
$TaskName = "VextHubAgent_Pulse"
$RunnerFile = Join-Path $InstallPath "run-agent.cmd"

function Get-FileContentCompat {
    param([string]$Path)

    if ((Get-Command Get-Content).Parameters.ContainsKey("Raw")) {
        return Get-Content $Path -Raw
    }

    return ([string]::Join("`n", (Get-Content $Path)))
}

Write-Host "[!] Iniciando instalacao do Agent..." -ForegroundColor Cyan

if (-not (Test-Path $InstallPath)) {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $SourceAgent)) {
    throw "agent.ps1 nao encontrado ao lado do instalador."
}

$config = $null
if (Test-Path $SourceConfig) {
    try {
        $raw = Get-FileContentCompat $SourceConfig
        if (Get-Command ConvertFrom-Json -ErrorAction SilentlyContinue) {
            $config = $raw | ConvertFrom-Json
        } else {
            $config = @{}
            $raw -split "," | ForEach-Object {
                if ($_ -match '"(.+)":\s*"(.+)"') {
                    $config[$matches[1]] = $matches[2]
                }
            }
        }
    } catch {}
}

if ($config) {
    if (-not $ServerUrl) { $ServerUrl = $config.server_url }
    if (-not $UnitName) { $UnitName = $config.unit }
    if (-not $TenantId -and $config.tenant_id) { $TenantId = [string]$config.tenant_id }
}

if ([string]::IsNullOrWhiteSpace($ServerUrl) -or [string]::IsNullOrWhiteSpace($UnitName)) {
    Write-Host "[!] Aviso: ServerUrl ou UnitName ausentes. Solicitando entrada manual..." -ForegroundColor Yellow
    if (-not $ServerUrl) { $ServerUrl = Read-Host "Informe a URL do servidor" }
    if (-not $UnitName) { $UnitName = Read-Host "Informe o nome da unidade" }
}

Copy-Item -Path $SourceAgent -Destination $AgentFile -Force

$jsonData = @{
    unit = $UnitName
    server_url = $ServerUrl.TrimEnd("/")
    interval_minutes = 10
}
if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
    $jsonData["tenant_id"] = $TenantId
}
($jsonData | ConvertTo-Json -Depth 6) | Set-Content -Path $ConfigFile -Force

$runnerContent = '@echo off' + "`r`n" +
    'powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "' + $AgentFile + '"' + "`r`n"
$runnerContent | Set-Content -Path $RunnerFile -Force

Write-Host "[!] Configurando inicializacao do agente..." -ForegroundColor Gray

$useModernTask = (Get-Module -ListAvailable ScheduledTasks) -and (Get-Command New-ScheduledTaskAction -ErrorAction SilentlyContinue)

if ($useModernTask) {
    try {
        $action = New-ScheduledTaskAction -Execute $RunnerFile
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)

        if ($trigger.PSObject.Properties.Name -contains "RepetitionInterval") {
            $trigger.RepetitionInterval = New-TimeSpan -Minutes 10
            $trigger.RepetitionDuration = [TimeSpan]::MaxValue
        }

        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable

        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
        Write-Host "[+] Persistencia configurada via ScheduledTask cmdlets." -ForegroundColor Green
    } catch {
        $useModernTask = $false
    }
}

if (-not $useModernTask) {
    Write-Host "[!] Usando schtasks.exe para compatibilidade legada..." -ForegroundColor Yellow
    schtasks.exe /Delete /TN "$TaskName" /F 2>$null | Out-Null
    $cmd = "`"$RunnerFile`""
    schtasks.exe /Create /SC MINUTE /MO 10 /TN "$TaskName" /TR "$cmd" /F 2>$null | Out-Null
}

Start-Process -FilePath $RunnerFile

Write-Host "[+] Instalacao concluida em $InstallPath." -ForegroundColor Green
Write-Host "[+] Inicializacao principal: $TaskName a cada 10 minutos." -ForegroundColor Green
Write-Host "[+] Inventario local sera salvo em: $InstallPath\inventory-last.json" -ForegroundColor Green
