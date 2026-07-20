# Configuration
$NativeRoot = "bindings/csharp/runtimes"
$Targets = @("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")

# 1. Clean up or ensure root exists
if (-not (Test-Path $NativeRoot)) { New-Item -ItemType Directory -Path $NativeRoot -Force }

foreach ($Target in $Targets) {
    # Map Rust target to .NET RID
    $Arch = if ($Target -like "*i686*") { "x86" } else { "x64" }
    $RidPath = Join-Path $NativeRoot "win-$Arch/native"
    
    Write-Host "--- Building for $Target ($Arch) ---" -ForegroundColor Cyan
    
    # 2. Run Cargo Build (using Release for the final bindings)
    cargo build --target $Target --release
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed for $Target"; continue }

    # 3. Ensure RID directory exists
    if (-not (Test-Path $RidPath)) { New-Item -ItemType Directory -Path $RidPath -Force }

    # 4. Copy Artifact
    $Source = "target/$Target/release/dll_syringe_bindings.dll"
    $Destination = Join-Path $RidPath "dll_syringe_bindings.dll"
    
    Write-Host "Exporting to: $Destination" -ForegroundColor Green
    Copy-Item -Path $Source -Destination $Destination -Force
}

Write-Host "`nAll builds complete." -ForegroundColor Yellow