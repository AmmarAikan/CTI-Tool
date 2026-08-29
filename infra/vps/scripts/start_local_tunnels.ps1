[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerHost,

    [Parameter(Mandatory = $true)]
    [string]$KeyPath,

    [string]$SshUser = "ammar",

    [ValidateRange(1, 65535)]
    [int]$RemotePort = 22,

    [ValidateRange(5, 180)]
    [int]$StartupTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$resolvedKey = (Resolve-Path -LiteralPath $KeyPath).Path
$ports = @(18088, 18090, 18443)
$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $ports }

if ($listeners) {
    $occupied = ($listeners | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ", "
    throw "Required local tunnel port(s) already in use: $occupied"
}

$sshArguments = @(
    "-i", $resolvedKey,
    "-p", "$RemotePort",
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-N",
    "-L", "18088:127.0.0.1:8088",
    "-L", "18090:127.0.0.1:8090",
    "-L", "18443:127.0.0.1:8443",
    "$SshUser@$ServerHost"
)

$process = Start-Process `
    -FilePath "$env:WINDIR\System32\OpenSSH\ssh.exe" `
    -ArgumentList $sshArguments `
    -WindowStyle Hidden `
    -PassThru

$deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
do {
    if ($process.HasExited) {
        throw "SSH tunnel process exited with code $($process.ExitCode)."
    }

    $ready = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in $ports } |
        Select-Object -ExpandProperty LocalPort -Unique
    if (@($ready).Count -eq $ports.Count) {
        break
    }

    Start-Sleep -Seconds 1
} while ([DateTime]::UtcNow -lt $deadline)

if (@($ready).Count -ne $ports.Count) {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    throw "SSH started but all three local forwarding ports were not opened."
}

[pscustomobject]@{
    ProcessId = $process.Id
    Gateway = "http://127.0.0.1:18088"
    ExternalControl = "http://127.0.0.1:18090"
    MISP = "https://127.0.0.1:18443"
}
