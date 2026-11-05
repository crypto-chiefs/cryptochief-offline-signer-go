$ErrorActionPreference = 'Stop'
$environmentNames = @('GOPROXY', 'GOSUMDB', 'GOTOOLCHAIN', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOWORK', 'GOFLAGS')
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $PSScriptRoot
try {
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $env:GOTOOLCHAIN = 'local'
    $env:GOWORK = 'off'
    $env:GOFLAGS = ''
    $env:CGO_ENABLED = '0'
    foreach ($targetOS in @('windows', 'linux')) {
        $env:GOOS = $targetOS
        $env:GOARCH = 'amd64'
        $dependencies = & go list -mod=vendor -deps ./...
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect $targetOS dependencies" }
        if ($dependencies | Where-Object { $_ -match '^(net($|/)|os/exec$|plugin$|.*(/rpc|/vault|/redis)(/|$))' }) {
            throw "Network or process-launch dependency in $targetOS runtime graph"
        }
        & go build -mod=vendor ./...
        if ($LASTEXITCODE -ne 0) { throw "$targetOS build failed" }
    }
    # Run tests for the host, independent of cross-compilation environment.
    $env:GOOS = & go env GOHOSTOS
    $env:GOARCH = & go env GOHOSTARCH
    & go test -mod=vendor ./... -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    & go vet -mod=vendor ./...
    if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
} finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    Pop-Location
}
