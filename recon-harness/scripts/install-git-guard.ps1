$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$gitRoot = (& git -C $projectRoot rev-parse --show-toplevel 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $gitRoot) {
    throw "Git 저장소가 아닙니다. git init 후 이 스크립트를 다시 실행하세요."
}

$hooks = Join-Path $projectRoot ".githooks"
$relative = [System.IO.Path]::GetRelativePath($gitRoot.Trim(), $hooks).Replace("\", "/")
& git -C $gitRoot.Trim() config core.hooksPath $relative
if ($LASTEXITCODE -ne 0) {
    throw "core.hooksPath 설정에 실패했습니다."
}

Write-Host "Secret commit guard enabled: $relative/pre-commit"
