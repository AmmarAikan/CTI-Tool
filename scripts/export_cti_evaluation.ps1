[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,79}$')]
    [string]$RunName = 'cti-live-v1',
    [ValidateRange(1, 500)]
    [int]$Size = 400,
    [string]$Seed = 'cti-live-v1'
)

$ErrorActionPreference = 'Stop'
$repositoryPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evaluationRoot = Join-Path $repositoryPath 'data\evaluation'
$destination = [System.IO.Path]::GetFullPath((Join-Path $evaluationRoot $RunName))
if (-not $destination.StartsWith($evaluationRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Invalid evaluation output scope.'
}
if (Test-Path -LiteralPath $destination) {
    throw 'This evaluation run already exists. Use a new RunName; do not overwrite annotations.'
}

Push-Location -LiteralPath $repositoryPath
$workerName = 'cti-evaluation-' + [Guid]::NewGuid().ToString('N')
$workerCreated = $false
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$stagingPath = Join-Path $temporaryRoot $workerName
$environmentBackup = @{}
try {
    docker info --format '{{.ServerVersion}}' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Docker is unavailable; no services were started.' }
    $databaseRunning = docker compose ps --status running --services
    if ($LASTEXITCODE -ne 0 -or 'db' -notin $databaseRunning) {
        throw 'Project PostgreSQL is not running. Start only the required database before exporting.'
    }
    $backendId = docker compose ps --all --quiet backend
    $databaseId = docker compose ps --quiet db
    if ($LASTEXITCODE -ne 0 -or -not $backendId -or -not $databaseId) {
        throw 'An existing backend image is required; this exporter will not install or build one.'
    }
    $backendImage = docker inspect $backendId --format '{{.Image}}'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the existing backend image.' }
    $databaseNetworks = docker inspect $databaseId --format '{{json .NetworkSettings.Networks}}' | ConvertFrom-Json
    $backendNetworks = docker inspect $backendId --format '{{json .NetworkSettings.Networks}}' | ConvertFrom-Json
    $sharedNetworks = @($databaseNetworks.PSObject.Properties.Name | Where-Object { $_ -in $backendNetworks.PSObject.Properties.Name })
    if ($sharedNetworks.Count -ne 1) { throw 'A single shared backend/database network is required.' }
    # Capture existing container environment internally, never print credentials.
    $containerEnvironment = docker inspect $backendId --format '{{json .Config.Env}}' | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the existing database configuration.' }
    $requiredKeys = @('POSTGRES_HOST', 'POSTGRES_PORT', 'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD')
    foreach ($key in $requiredKeys) {
        $entry = @($containerEnvironment | Where-Object { $_.StartsWith($key + '=') })
        if ($entry.Count -ne 1) { throw "Missing required configuration: $key" }
        $environmentBackup[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $entry[0].Substring($key.Length + 1), 'Process')
    }
    if (-not (Test-Path -LiteralPath $evaluationRoot)) {
        $null = New-Item -ItemType Directory -Path $evaluationRoot
    }
    # No bind mounts: avoid Docker Desktop file-sharing dependencies. This
    # disposable worker receives only code, no .env, models, datasets or keys.
    $null = docker create --pull never --name $workerName --label 'cti.maintenance=live-evaluation' `
        --network $sharedNetworks[0] --entrypoint python --workdir /app `
        --env POSTGRES_HOST --env POSTGRES_PORT --env POSTGRES_DB --env POSTGRES_USER --env POSTGRES_PASSWORD `
        --env 'PGOPTIONS=-c default_transaction_read_only=on' `
        $backendImage scripts/cti_live_evaluation.py export `
        --output "/app/data/evaluation/$RunName" --size $Size --seed $Seed
    if ($LASTEXITCODE -ne 0) { throw 'Temporary evaluation worker could not be created.' }
    $workerCreated = $true
    $scriptDirectory = Join-Path $stagingPath 'scripts'
    $null = New-Item -ItemType Directory -Path $scriptDirectory -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'cti_live_evaluation.py') -Destination $scriptDirectory
    $copies = @(
        @('backend/app/services/cti_evaluation_service.py', '/app/backend/app/services/cti_evaluation_service.py'),
        @('backend/app/pipeline/extraction/ioc_extractor.py', '/app/backend/app/pipeline/extraction/ioc_extractor.py'),
        @('backend/app/pipeline/extraction/ner_extractor.py', '/app/backend/app/pipeline/extraction/ner_extractor.py'),
        @('ml/common', '/app/ml'),
        @('ml/evaluation', '/app/ml/evaluation')
    )
    foreach ($copy in $copies) {
        docker cp (Join-Path $repositoryPath $copy[0]) "${workerName}:$($copy[1])"
        if ($LASTEXITCODE -ne 0) { throw 'Failed to copy evaluation code to the temporary worker.' }
    }
    docker cp $scriptDirectory "${workerName}:/app/scripts"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to copy the maintenance entry point.' }
    docker start --attach $workerName
    if ($LASTEXITCODE -ne 0) { throw 'Read-only evaluation worker failed; no application data was committed.' }
    $workerExitCode = docker inspect $workerName --format '{{.State.ExitCode}}'
    if ($LASTEXITCODE -ne 0 -or $workerExitCode -ne '0') { throw 'Evaluation worker did not finish successfully.' }
    docker cp "${workerName}:/app/data/evaluation/$RunName" $evaluationRoot
    if ($LASTEXITCODE -ne 0) { throw 'Evaluation output copy did not complete; validate before using it.' }
}
finally {
    foreach ($key in $environmentBackup.Keys) {
        [Environment]::SetEnvironmentVariable($key, $environmentBackup[$key], 'Process')
    }
    if ($workerCreated) {
        # No force: do not destroy a still-running worker after an interruption.
        docker rm $workerName | Out-Null
    }
    if (Test-Path -LiteralPath $stagingPath) {
        $resolvedStaging = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $stagingPath).Path)
        if ($resolvedStaging -eq $stagingPath -and $resolvedStaging.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
        }
    }
    Pop-Location
}
