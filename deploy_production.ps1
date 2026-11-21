# MALGUARD AI - Production Deployment Script
# Staged UI cleanup, merges verified preview-clamav into main, and triggers Vercel Production Deployment

$gitCandidates = @(
    "git",
    "C:\Users\mahes\AppData\Local\MinGit\cmd\git.exe",
    "C:\Users\$env:USERNAME\AppData\Local\MinGit\cmd\git.exe",
    "C:\Program Files\Git\cmd\git.exe",
    "C:\Program Files (x86)\Git\cmd\git.exe",
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Git\cmd\git.exe"
)

$gitExe = $null
foreach ($candidate in $gitCandidates) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $gitExe = $candidate
        break
    }
    if (Test-Path $candidate -ErrorAction SilentlyContinue) {
        $gitExe = $candidate
        break
    }
}

if (-not $gitExe) {
    Write-Error "Git executable not found in PATH or standard MinGit directories."
    exit 1
}

Write-Host "Using Git binary: $gitExe" -ForegroundColor Cyan

Write-Host "=== 1. Creating backup branch from current main commit (12af6b2) ===" -ForegroundColor Cyan
& $gitExe branch backup-main-before-clamav 12af6b2
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Backup branch already exists or branch command returned code $LASTEXITCODE"
}

Write-Host "=== 2. Checking out main branch ===" -ForegroundColor Cyan
& $gitExe checkout main
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to checkout main branch"
    exit 1
}

Write-Host "=== 3. Fast-forward merging preview-clamav into main ===" -ForegroundColor Cyan
& $gitExe merge --ff-only preview-clamav
if ($LASTEXITCODE -ne 0) {
    Write-Error "Fast-forward merge failed. Merge aborted to protect production integrity."
    exit 1
}

Write-Host "=== 4. Staging UI cleanup changes ===" -ForegroundColor Cyan
& $gitExe add src/components/dashboard/DashboardHeader.tsx src/components/scanner/EngineStatusBanner.tsx
& $gitExe commit -m "fix(ui): remove AI Detection Engine badge from header and Vercel URL from engine banner"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Working directory already clean."
}

Write-Host "=== 5. Pushing backup-main-before-clamav to remote origin ===" -ForegroundColor Cyan
& $gitExe push origin backup-main-before-clamav

Write-Host "=== 6. Pushing main to remote origin to trigger Vercel Production Build ===" -ForegroundColor Green
& $gitExe push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push main branch to origin."
    exit 1
}

Write-Host "=== SUCCESS: Production deployment triggered on Vercel ===" -ForegroundColor Green
Write-Host "Production URL: https://malguard-ai-amber.vercel.app"
Write-Host "Health check endpoint: https://malguard-ai-amber.vercel.app/api/v1/health"
