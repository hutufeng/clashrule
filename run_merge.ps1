# Clash Rules Merge - PowerShell Helper Script

Write-Host ">>> Starting Clash Rules Merger..." -ForegroundColor Cyan

$pythonCandidates = @(
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "$env:ProgramFiles\Python312\python.exe",
    "$env:ProgramFiles\Python311\python.exe",
    "$env:ProgramFiles\Python310\python.exe"
)

$targetPython = $null
foreach ($cand in $pythonCandidates) {
    if (Test-Path $cand) {
        $targetPython = $cand
        break
    }
}

if (-not $targetPython) {
    $cmd = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($cmd -and ($cmd.Source -notlike "*WindowsApps*")) {
        $targetPython = $cmd.Source
    } else {
        $targetPython = "py"
    }
}

Write-Host ">>> Python: $targetPython" -ForegroundColor Gray

& $targetPython merge.py

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host ">>> [SUCCESS] Merge completed successfully!" -ForegroundColor Green
    Write-Host "  - Rules output: rules/" -ForegroundColor Gray
    Write-Host "  - Clash snippet: clash_config_snippet.yaml" -ForegroundColor Gray
    Write-Host "  - Execution log: SYNC_LOG.md" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host ""
    Write-Host ">>> [ERROR] Merge script failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    Write-Host ""
}
