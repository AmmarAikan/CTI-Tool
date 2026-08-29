[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerHost,

    [Parameter(Mandatory = $true)]
    [string]$KeyPath,

    [string]$SshUser = "ammar"
)

$ErrorActionPreference = "Stop"
$resolvedKey = (Resolve-Path -LiteralPath $KeyPath).Path
$ports = @(18088, 18443)
$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $ports }

if ($listeners) {
    $occupied = ($listeners | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ", "
    throw "Required local tunnel port(s) already in use: $occupied"
}

$sshArguments = @(
    "-i", $resolvedKey,
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-N",
    "-L", "18088:127.0.0.1:8088",
    "-L", "18443:127.0.0.1:8443",
    "$SshUser@$ServerHost"
)

$process = Start-Process `
    -FilePath "$env:WINDIR\System32\OpenSSH\ssh.exe" `
    -ArgumentList $sshArguments `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Seconds 3
if ($process.HasExited) {
    throw "SSH tunnel process exited with code $($process.ExitCode)."
}

$ready = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $ports } |
    Select-Object -ExpandProperty LocalPort -Unique

if (@($ready).Count -ne $ports.Count) {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    throw "SSH started but both local forwarding ports were not opened."
}

[pscustomobject]@{
    ProcessId = $process.Id
    Gateway = "http://127.0.0.1:18088"
    MISP = "https://127.0.0.1:18443"
}
