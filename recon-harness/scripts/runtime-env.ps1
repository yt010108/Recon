$ProjectRoot = Split-Path -Parent $PSScriptRoot
$NodeHome = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot ".runtime") -Directory -Filter "node-v*-win-x64" |
    Sort-Object Name -Descending |
    Select-Object -First 1
$PiHome = Join-Path $ProjectRoot ".runtime\pi"

if (-not $NodeHome -or -not (Test-Path -LiteralPath (Join-Path $NodeHome.FullName "node.exe"))) {
    throw "Portable Node.js is missing. Run .\scripts\install-pi.ps1 first."
}
if (-not (Test-Path -LiteralPath (Join-Path $PiHome "pi.cmd"))) {
    throw "Pi is missing. Run .\scripts\install-pi.ps1 first."
}

$env:Path = "$($NodeHome.FullName);$PiHome;$env:Path"

