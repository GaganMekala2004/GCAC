$baseDir = Split-Path -Parent $PSScriptRoot
$sampleRepos = Join-Path $baseDir 'sample-repos'
if (-not (Test-Path $sampleRepos)) {
    New-Item -ItemType Directory -Path $sampleRepos -Force | Out-Null
}

function Copy-And-Clean-Repo($srcWorkspace, $destName) {
    $src = Join-Path $baseDir "workspaces\$srcWorkspace\repository"
    $dst = Join-Path $sampleRepos $destName
    if (-not (Test-Path $dst) -and (Test-Path $src)) {
        Copy-Item -Path $src -Destination $dst -Recurse -Force
        Push-Location $dst
        git checkout main 2>&1 | Out-Null
        git reset --hard 2>&1 | Out-Null
        git clean -fdx 2>&1 | Out-Null
        Pop-Location
    }
}

Copy-And-Clean-Repo 'VUL-POC-002' 'customer-service'
Copy-And-Clean-Repo 'VUL-POC-001' 'payments-api'
Copy-And-Clean-Repo 'VUL-POC-003' 'inventory-manager'
Copy-And-Clean-Repo 'VUL-POC-004' 'identity-provider'
Copy-And-Clean-Repo 'VUL-POC-011' 'storefront-api'
Copy-And-Clean-Repo 'GCAS-E2E-004' 'gcas-agentic-e2e-test-repo'

# Ensure customer-service baseline has permitAll()
$secFile = Join-Path $sampleRepos 'customer-service\src\main\java\com\example\customer\config\SecurityConfig.java'
if (Test-Path $secFile) {
    $content = Get-Content $secFile -Raw
    if ($content -match 'hasRole') {
        $content = $content.Replace('.hasRole("ADMIN")', '.permitAll() // Vulnerable authorization flaw!')
        Set-Content $secFile -Value $content -NoNewline
        Push-Location (Join-Path $sampleRepos 'customer-service')
        git commit -am 'Ensure vulnerable baseline' 2>&1 | Out-Null
        Pop-Location
    }
}

Write-Output "Sample repositories initialized at $sampleRepos"
