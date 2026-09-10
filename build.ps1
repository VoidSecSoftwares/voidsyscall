$ErrorActionPreference = "Stop"

$buildDir = Join-Path $PSScriptRoot "build"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$env:GOOS = "windows"
$env:GOARCH = "amd64"

Write-Host "[+] Building agent (windows/amd64)..."
go build -ldflags="-s -w" -o (Join-Path $buildDir "voidsyscall-agent.exe") ./cmd/agent
Write-Host "[+] Building server (windows/amd64)..."
go build -ldflags="-s -w" -o (Join-Path $buildDir "voidsyscall-server.exe") ./cmd/server

$env:GOOS = "linux"
Write-Host "[+] Building server (linux/amd64)..."
go build -ldflags="-s -w" -o (Join-Path $buildDir "voidsyscall-server-linux") ./cmd/server

$env:GOOS = "darwin"
$env:GOARCH = "arm64"
Write-Host "[+] Building server (darwin/arm64)..."
go build -ldflags="-s -w" -o (Join-Path $buildDir "voidsyscall-server-darwin") ./cmd/server

Remove-Item Env:GOOS
Remove-Item Env:GOARCH

Write-Host "[+] All builds complete in $buildDir"