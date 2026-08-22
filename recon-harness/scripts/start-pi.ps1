param(
    [ValidateSet("openai-codex", "openai")]
    [string]$Provider = "openai-codex",
    [string]$Model = ""
)

# Launch pi at the workspace root so AGENTS.md, .pi/ extensions, skills, and
# prompts load no matter which subfolder the work ends up touching.
$ErrorActionPreference = "Stop"
$WorkspaceRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location -LiteralPath $WorkspaceRoot
$Pi = Get-Command pi.cmd -ErrorAction Stop
$PiArguments = @("--provider", $Provider)
if ($Model) { $PiArguments += @("--model", $Model) }
& $Pi.Source @PiArguments
