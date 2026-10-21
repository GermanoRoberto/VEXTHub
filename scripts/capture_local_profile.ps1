param(
  [string]$OutputPath = ".\scratch\local-machine-profile.json",
  [int]$MaxPrograms = 260
)

$ErrorActionPreference = "SilentlyContinue"

function Get-RegistryPrograms {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $items = foreach ($path in $paths) {
    Get-ItemProperty -Path $path | Where-Object { $_.DisplayName } | ForEach-Object {
      [pscustomobject]@{
        name = $_.DisplayName
        version = $_.DisplayVersion
        publisher = $_.Publisher
        install_date = $_.InstallDate
      }
    }
  }

  $items |
    Sort-Object name, version -Unique |
    Select-Object -First $MaxPrograms
}

function Get-SecurityProducts {
  $products = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct
  if (-not $products) {
    return @()
  }

  $products | ForEach-Object {
    [pscustomobject]@{
      name = $_.displayName
      instance_guid = $_.instanceGuid
      product_state = $_.productState
      path_to_signed_product_exe = $_.pathToSignedProductExe
      path_to_signed_reporting_exe = $_.pathToSignedReportingExe
    }
  }
}

function Test-CurrentUserIsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$bios = Get-CimInstance -ClassName Win32_BIOS
$drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  [pscustomobject]@{
    device_id = $_.DeviceID
    size_gb = [math]::Round($_.Size / 1GB, 2)
    free_gb = [math]::Round($_.FreeSpace / 1GB, 2)
  }
}
$network = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
  [pscustomobject]@{
    description = $_.Description
    mac = $_.MACAddress
    ip = @($_.IPAddress)
    gateway = @($_.DefaultIPGateway)
    dns_domain = $_.DNSDomain
  }
}

$profile = [ordered]@{
  generated_at = (Get-Date).ToString("o")
  collection_mode = "read_only"
  hostname = $env:COMPUTERNAME
  active_user = "$env:USERDOMAIN\$env:USERNAME"
  is_admin_session = (Test-CurrentUserIsAdmin)
  os = [ordered]@{
    caption = $os.Caption
    version = $os.Version
    build_number = $os.BuildNumber
    architecture = $os.OSArchitecture
    install_date = $os.InstallDate
  }
  hardware = [ordered]@{
    manufacturer = $computer.Manufacturer
    model = $computer.Model
    cpu = $cpu.Name
    logical_processors = $cpu.NumberOfLogicalProcessors
    memory_gb = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
    serial_number = $bios.SerialNumber
  }
  security_products = @(Get-SecurityProducts)
  drives = @($drives)
  network = @($network)
  programs = @(Get-RegistryPrograms)
}

$resolved = Resolve-Path -Path "." | Select-Object -ExpandProperty Path
$fullOutput = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
  $OutputPath
} else {
  Join-Path $resolved $OutputPath
}
$dir = Split-Path -Parent $fullOutput
if (!(Test-Path $dir)) {
  New-Item -ItemType Directory -Path $dir | Out-Null
}

$profile | ConvertTo-Json -Depth 8 | Set-Content -Path $fullOutput -Encoding UTF8
Write-Host "Local machine profile captured: $fullOutput"
