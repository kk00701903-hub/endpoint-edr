<#
  Endpoint EDR 빌드 스크립트 — Cursor 터미널(PowerShell)에서 실행
    .\scripts\build.ps1          # 가드레일 검사 → 에이전트 빌드 → 서버 컴파일 확인 → 관리 콘솔 빌드
    .\scripts\build.ps1 -Tidy    # 의존성 정리(go mod tidy)까지 (처음 1회, go.mod 변경 시)
  결과물: agent\dist\edr-agent-amd64.exe, agent\dist\edr-agent-arm64.exe (커밋 대상 아님)
#>
param([switch]$Tidy)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }

function Fail($msg) {
    Write-Host "❌ $msg" -ForegroundColor Red
    Restore-Env
    exit 1
}
function Restore-Env {
    foreach ($k in $saved.Keys) {
        if ($null -eq $saved[$k]) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
        else { Set-Item "Env:$k" $saved[$k] }
    }
    Set-Location $root
}
function Step($msg) { Write-Host "`n▶ $msg" -ForegroundColor Cyan }

Set-Location $root

# 버전: git 태그 또는 커밋 해시
$version = (& git describe --tags --always 2>$null)
if (-not $version) { $version = "0.1.0-dev" }

# 1) 읽기 전용 가드레일 (Git Bash 우선 — WSL 의 bash 는 경로가 달라 쓰지 않음)
Step "읽기 전용 가드레일 검사"
$gitBash = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($gitBash) {
    & $gitBash "scripts/check-passive.sh"
    if ($LASTEXITCODE -ne 0) { Fail "가드레일 검사 실패 — 에이전트에 시스템 개입 코드가 있습니다" }
} else {
    Write-Warning "Git Bash 를 찾지 못해 가드레일 검사를 건너뜁니다 (Git for Windows 설치 권장)"
}

# 2) 에이전트 (Windows 실행 파일)
Step "에이전트 빌드"
Set-Location "$root\agent"
if ($Tidy -or -not (Test-Path "go.sum")) {
    go mod tidy
    if ($LASTEXITCODE -ne 0) { Fail "agent: go mod tidy 실패" }
}
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
New-Item -ItemType Directory -Force -Path "dist" | Out-Null
foreach ($arch in @("amd64", "arm64")) {
    $env:GOARCH = $arch
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "dist\edr-agent-$arch.exe" .\cmd\edr-agent
    if ($LASTEXITCODE -ne 0) { Fail "agent: 빌드 실패 ($arch)" }
}
$env:GOARCH = "amd64"
go vet ./...
if ($LASTEXITCODE -ne 0) { Fail "agent: go vet 실패" }

# 3) 서버 (Docker 에서 돌 Linux 용 — 컴파일 확인만)
Step "서버(ingest·enricher) 컴파일 확인"
Set-Location "$root\services"
if ($Tidy -or -not (Test-Path "go.sum")) {
    go mod tidy
    if ($LASTEXITCODE -ne 0) { Fail "services: go mod tidy 실패" }
}
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build ./...
if ($LASTEXITCODE -ne 0) { Fail "services: 빌드 실패" }
go vet ./...
if ($LASTEXITCODE -ne 0) { Fail "services: go vet 실패" }

# 4) 관리 콘솔 (Next.js) — Node.js 와 pnpm 이 있을 때만
Restore-Env
Step "관리 콘솔(apps/web) 빌드"
$pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
if ($pnpm) {
    Set-Location "$root\apps\web"
    pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { Fail "console: pnpm install 실패" }
    pnpm lint
    if ($LASTEXITCODE -ne 0) { Fail "console: lint 실패" }
    pnpm build
    if ($LASTEXITCODE -ne 0) { Fail "console: 빌드 실패" }
} else {
    Write-Warning "pnpm 이 없어 콘솔 빌드를 건너뜁니다 (npm i -g pnpm)"
}

Restore-Env
Write-Host "`n✅ 빌드 완료 (version $version)" -ForegroundColor Green
Get-ChildItem "$root\agent\dist\*.exe" | ForEach-Object { "   {0}  ({1:N1} MB)" -f $_.FullName, ($_.Length / 1MB) }
Write-Host "   go.sum 이 새로 생기거나 바뀌었으면 함께 커밋하세요."
