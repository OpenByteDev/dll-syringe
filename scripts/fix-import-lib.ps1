param(
    [Parameter(Mandatory)] [string]$DllPath,
    [Parameter(Mandatory)] [string]$DllName,
    [Parameter(Mandatory)] [string]$OutLib,
    [Parameter(Mandatory)] [string]$Machine
)

$ErrorActionPreference = "Stop"

$defPath = [System.IO.Path]::ChangeExtension($OutLib, ".def")

$exports = dumpbin /exports $DllPath |
    Select-String '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)' |
    ForEach-Object { $_.Matches[0].Groups[1].Value }
if (-not $exports) {
    throw "No exports found in $DllPath"
}

$defLines = @("LIBRARY $DllName", "EXPORTS") + $exports
Set-Content -Path $defPath -Value $defLines -Encoding ascii

lib /def:$defPath /out:$OutLib /machine:$Machine /nologo
if ($LASTEXITCODE -ne 0) {
    throw "lib.exe failed with exit code $LASTEXITCODE"
}

Remove-Item ([System.IO.Path]::ChangeExtension($OutLib, ".exp")) -ErrorAction SilentlyContinue
