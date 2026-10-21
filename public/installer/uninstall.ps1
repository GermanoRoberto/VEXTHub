[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$InstallPath = Join-Path $env:LOCALAPPDATA "VextHub\AgentLegacy"
$TaskName = "VextHubAgent_Pulse"

Write-Host "--- VextHub Agent Uninstaller ---" -ForegroundColor Yellow

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Tarefa agendada removida."
    }
} else {
    schtasks.exe /Delete /TN "$TaskName" /F 2>$null | Out-Null
}

Write-Host "[*] Encerrando processos do agente..." -ForegroundColor Gray
try {
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'"
    foreach ($p in $processes) {
        if ($p.CommandLine -like "*agent.ps1*") {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Agente (PID: $($p.ProcessId)) encerrado." -ForegroundColor Yellow
        }
    }
} catch {}

if (Test-Path $InstallPath) {
    Remove-Item -Path $InstallPath -Recurse -Force
    Write-Host "Arquivos removidos de $InstallPath."
}

Write-Host "`nDesinstalacao concluida com sucesso." -ForegroundColor Green
