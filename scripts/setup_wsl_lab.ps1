$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host '============================================================'
Write-Host 'NESS Cyber Range - One-time WSL2 Setup (No Docker)'
Write-Host '============================================================'
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  Write-Host 'WSL is not installed. Run: wsl --install -d Ubuntu' -ForegroundColor Red
  exit 1
}
$distros = @(wsl.exe -l -q | ForEach-Object { $_.Replace([char]0,'').Trim() } | Where-Object { $_ -and $_ -notmatch 'docker' })
if ($distros.Count -eq 0) {
  Write-Host 'No Linux distribution was found. Run: wsl --install -d Ubuntu' -ForegroundColor Red
  exit 1
}
$Distro = $distros[0]
Write-Host "Using WSL distribution: $Distro"
$wslRoot = (wsl.exe -d $Distro -- wslpath -a -u "$Root").Trim()
if (-not $wslRoot) { throw 'Could not translate the NESS project path into WSL.' }
Write-Host 'Linux will ask for your WSL sudo password once during installation.' -ForegroundColor Yellow
wsl.exe -d $Distro -- bash "$wslRoot/lab/linux/install_lab.sh"
if ($LASTEXITCODE -ne 0) { throw "Cyber-range installation failed with exit code $LASTEXITCODE" }
Write-Host 'Setup completed successfully.' -ForegroundColor Green
Write-Host 'You can now run run_windows.bat and press Start Lab from Network Topology.'
Read-Host 'Press Enter to close'
