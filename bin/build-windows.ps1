# Builds a standalone Windows app (no Python needed by the end user).
# Run from anywhere: it figures out the project root. Output: dist\LMSFuzzer\LMSFuzzer.exe
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
Set-Location $root

Write-Host "Building LMS Fuzzer (Windows)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean --windowed `
    --name LMSFuzzer `
    --icon "assets\logo.ico" `
    --add-data "assets;assets" `
    "bin\gui.py"

# Ship the default data folders next to the exe so users can drop in their own files
# and the app has somewhere to write results/bodies.
$dist = Join-Path $root "dist\LMSFuzzer"
foreach ($d in @("Requests","payloads","results","bodies")) {
    New-Item -ItemType Directory -Force (Join-Path $dist $d) | Out-Null
}
Copy-Item "payloads\*" (Join-Path $dist "payloads") -Force -ErrorAction SilentlyContinue
Copy-Item "Requests\sample*" (Join-Path $dist "Requests") -Force -ErrorAction SilentlyContinue
Copy-Item "README.md" $dist -Force -ErrorAction SilentlyContinue

Write-Host "`nDone. Share the whole folder:" -ForegroundColor Green
Write-Host "  $dist"
Write-Host "Users double-click LMSFuzzer.exe inside it. No Python required."
