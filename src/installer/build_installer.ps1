[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$SourceFile = Join-Path $ScriptDir "VextHubAgent.cs"
$OutputFile = Join-Path $ScriptDir "VextHub_Agent.exe"

# Matar o agente se estiver rodando para permitir a gravação do arquivo
Get-Process VextHubAgent -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
$IconFile = Join-Path $RepoRoot "public\vext_logo.ico"

# Forçamos o uso do ícone se ele existir, senão usamos o fallback do sistema
if (-not (Test-Path $IconFile)) {
    Write-Warning "vext_logo.ico não encontrado em public/"
}


$cscCandidates = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

$csc = $null
foreach ($candidate in $cscCandidates) {
    if (Test-Path $candidate) {
        $csc = $candidate
        break
    }
}

if (-not $csc) {
    throw "csc.exe not found. Install .NET Framework developer tools or build the agent on a Windows host with csc.exe."
}

$args = @(
    "/target:winexe",
    "/optimize+",
    "/out:`"$OutputFile`"",
    "/r:System.dll",
    "/r:System.Drawing.dll",
    "/r:System.Management.dll",
    "/r:System.Windows.Forms.dll",
    "/r:System.ServiceProcess.dll"
)

# O csc legado falha com ícones modernos (CS1567). 
# O agente carregará o ícone dinamicamente via ResolveIcon()
$args += "`"$SourceFile`""

Write-Host "Compiling with csc..."
& $csc $args
$exitCode = $LASTEXITCODE

$AgentAlias = Join-Path $ScriptDir "VextHubAgent.exe"
Copy-Item -Path $OutputFile -Destination $AgentAlias -Force
Write-Host "Built $OutputFile and $AgentAlias"
