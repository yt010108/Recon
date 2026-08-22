$ErrorActionPreference = "Stop"

$PiVersion = "0.84.2"
$Node = Get-Command node.exe -ErrorAction Stop
$Npm = Get-Command npm.cmd -ErrorAction Stop
& $Npm.Source install --global --ignore-scripts "@earendil-works/pi-coding-agent@$PiVersion"
if ($LASTEXITCODE -ne 0) { throw "Shared Pi installation failed." }
$Pi = Get-Command pi.cmd -ErrorAction Stop
Write-Host "Node: $($Node.Source)"
& $Pi.Source --version
Write-Host "Shared Pi is available as: pi"
