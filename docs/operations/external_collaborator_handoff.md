# External Sources Collaborator Handoff

## Scope

The collaborator computer owns only External Sources collection, local review, and the versioned JSON handoff. BERT, Regex IoC extraction, correlation, risk scoring, PostgreSQL, Internal Sources, and MISP delivery remain on Ammar's computer or the private VPS services.

The collaborator receives only:

- a dedicated SSH public-key identity that can create the Gateway tunnel;
- the publish-only Gateway token;
- the repository branch containing the canonical External Sources implementation.

Do not give the collaborator the feed-read token, sensor-read token, response HMAC secrets, MISP key, PostgreSQL credentials, or Ammar's SSH private key.

## One-time readiness gates

Before the collaborator starts:

1. Publish the approved integration branch to the shared GitHub repository.
2. On the collaborator computer, create a dedicated Ed25519 key and send only the `.pub` file to the VPS administrator:

```powershell
ssh-keygen -t ed25519 -a 64 -f "$env:USERPROFILE\.ssh\cti_external_publisher" -C "cti-external-publisher"
```

3. The administrator creates a dedicated VPS account and restricts that public key to Gateway port forwarding. The private key never leaves the collaborator computer.
4. Transfer `.vps-publisher.env` through an approved private channel. Keep it outside Git.
5. Install Docker Desktop with Linux containers and Git on the collaborator computer.

## Repository and local collector setup

After the branch has been published:

```powershell
git clone https://github.com/AmmarAikan/CTI-Tool.git
Set-Location CTI-Tool
git fetch origin
git switch --track origin/newBackend-cloud-integration

Copy-Item .env.external.example .env.external.local
Copy-Item config/dark_web_sources.example.json config/dark_web_sources.local.json
```

Set a strong, local-only `EXTERNAL_API_TOKEN` in `.env.external.local`. Real onion addresses, credentials, cookies, and API keys must remain in ignored local configuration and must never enter the handoff JSON.

Start only the External Sources service:

```powershell
docker compose -f compose.external.yml config
docker compose -f compose.external.yml up -d --build
docker compose -f compose.external.yml ps
curl.exe --fail http://127.0.0.1:8000/api/v1/external-sources/health
```

This `127.0.0.1:8000` belongs to the collaborator computer. It is not Ammar's central FastAPI service and must not be exposed publicly.

## Collect and obtain the validated JSON

Set the same local collector token in the current PowerShell session, then start a bounded collection job:

```powershell
$env:EXTERNAL_API_TOKEN = "<same-local-token-from-.env.external.local>"
$headers = @{
    Authorization = "Bearer $env:EXTERNAL_API_TOKEN"
    "Idempotency-Key" = [guid]::NewGuid().ToString()
}

$job = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/external-sources/jobs" `
    -Headers $headers `
    -ContentType "application/json" `
    -Body '{"scope":"all_enabled","force":false}'

$job
```

Poll the returned `job_id` until its state is terminal:

```powershell
Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/v1/external-sources/jobs/$($job.job_id)" `
    -Headers @{ Authorization = "Bearer $env:EXTERNAL_API_TOKEN" }
```

Download the latest validated export without reserializing it:

```powershell
$artifact = Join-Path $PWD "external_handoff_latest.json"
curl.exe --fail-with-body --silent --show-error `
    -H "Authorization: Bearer $env:EXTERNAL_API_TOKEN" `
    --output $artifact `
    "http://127.0.0.1:8000/api/v1/external-sources/exports/latest"
```

The response contains the canonical `dataset` plus its validated manifest summary. Review/rejected records are not included in the accepted dataset.

## Publish through the private VPS Gateway

Start the encrypted SSH tunnel with the collaborator's dedicated key and VPS user:

```powershell
.\infra\vps\scripts\start_local_tunnels.ps1 `
    -ServerHost <VPS_IP> `
    -KeyPath "$env:USERPROFILE\.ssh\cti_external_publisher" `
    -SshUser <COLLABORATOR_VPS_USER>
```

Load the ignored publish-only fragment without printing it:

```powershell
$publisher = @{}
Get-Content .vps-publisher.env | ForEach-Object {
    if ($_ -match '^([^#][^=]*)=(.*)$') {
        $publisher[$matches[1].Trim()] = $matches[2].Trim()
    }
}

curl.exe --fail-with-body --silent --show-error `
    -X POST `
    -H "Authorization: Bearer $($publisher.EXTERNAL_FEED_PUBLISH_TOKEN)" `
    -H "Content-Type: application/json" `
    --data-binary "@$artifact" `
    "$($publisher.EXTERNAL_FEED_PUBLISH_URL)"
```

The successful response must contain `status=accepted`, `feed_id`, `item_count`, and `etag`. It must not contain a read token or any MISP/sensor credential.

After publication, Ammar pulls the feed through the central authenticated FastAPI endpoint:

```text
POST /api/v1/integrations/external-feed/pull
```

The central backend then performs BERT/Regex extraction, CTI normalization, PostgreSQL persistence, correlation, risk scoring, STIX, and optional unpublished MISP delivery.

## Acceptance checklist

- Collector health returns HTTP 200.
- The collection job reaches `completed` or a documented partial state.
- Latest Export passes the canonical manifest and item validation.
- Gateway publish returns HTTP 202 and the expected item count.
- Ammar's first pull creates a completed run and expected External CTI records.
- Re-publishing and re-pulling identical data creates no duplicate CTI records; the read path may return HTTP 304.
- No secret, private onion address, cookie, authorization header, or local filesystem path appears in Git or the handoff artifact.

## Current operational boundary

The integration branch must be visible on GitHub and the collaborator's restricted VPS SSH identity must be installed before this handoff can be executed from another computer. A locally committed branch or an unshared SSH key is not a completed team handoff.
