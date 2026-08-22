$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $ProjectRoot "lab\compose.yaml"

docker compose -f $ComposeFile up -d
if ($LASTEXITCODE -ne 0) {
    throw "Could not start OWASP Juice Shop."
}

Write-Host "Juice Shop host URL: http://127.0.0.1:3000"
Write-Host "Recon worker URL:   http://recon-juice-shop:3000 (network: recon-lab)"
