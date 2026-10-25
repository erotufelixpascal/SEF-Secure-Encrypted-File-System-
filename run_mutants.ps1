<#
.SYNOPSIS
  Scores one test suite against every seeded fault (Step 7 / Step 10).
.EXAMPLE
  .\run_mutants.ps1 -Tests tests\manual
  .\run_mutants.ps1 -Tests tests\ai\run1 -MutantsDir D:\held_out\mutants
.NOTES
  For each patch: apply, rebuild, run the suite, record detected/missed, revert.
  "build_error" means the patch is broken: fix it and rerun; never count it.
  Run from the repository root in a Developer PowerShell, with no uncommitted changes in src\.
#>
param(
    [Parameter(Mandatory = $true)][string]$Tests,
    [string]$MutantsDir = "mutants",
    [string]$BuildDir = "build"
)

# Not "Stop": in Windows PowerShell 5.1 that turns any native stderr output (git, cmake) into an exception
$ErrorActionPreference = "Continue"
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

$dirty = git status --porcelain -- src
if ($dirty) { throw "src\ has uncommitted changes; commit or stash them so every fault starts from sefs-v1.0." }

$rows = @()
$patches = Get-ChildItem (Join-Path $MutantsDir "*.patch") | Sort-Object Name
if (-not $patches) { throw "No .patch files in $MutantsDir" }

foreach ($p in $patches) {
    $status = "build_error"
    $start = Get-Date
    git apply --check $p.FullName 2>$null
    if ($LASTEXITCODE -eq 0) {
        git apply $p.FullName
        try {
            cmake --build $BuildDir --config Debug | Out-Null
            if ($LASTEXITCODE -eq 0) {
                & $python -m pytest $Tests -q -x -p no:cacheprovider | Out-Null
                # pytest exit 1 = tests failed (fault detected); anything else (e.g. 2, 4, 5) is a run problem
                $status = switch ($LASTEXITCODE) { 0 { "missed" } 1 { "detected" } default { "run_error" } }
            }
        }
        finally {
            git apply -R $p.FullName
        }
    }
    $secs = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
    Write-Host ("{0,-30} {1}" -f $p.BaseName, $status)
    $rows += [pscustomobject]@{ fault = $p.BaseName; suite = $Tests; result = $status; seconds = $secs }
}

cmake --build $BuildDir --config Debug | Out-Null   # rebuild clean code
New-Item -ItemType Directory -Force analysis | Out-Null
$name = ($Tests -replace '[\\/]', '_')
$out = "analysis\mutants_$name.csv"
$rows | Export-Csv $out -NoTypeInformation -Encoding utf8
Write-Host "Wrote $out"
