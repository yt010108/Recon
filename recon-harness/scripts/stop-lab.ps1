$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $ProjectRoot "lab\compose.yaml"

$Members = docker network inspect recon-lab --format '{{range .Containers}}{{.Name}}{{"\n"}}{{end}}' 2>$null
if ($LASTEXITCODE -eq 0 -and $Members -contains "kali") {
    docker network disconnect recon-lab kali
}

docker compose -f $ComposeFile down

