#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GOFLAGS= CGO_ENABLED=0

for target_os in windows linux; do
    printf 'Checking %s/amd64 dependencies and build...\n' "$target_os"
    dependencies=$(GOOS="$target_os" GOARCH=amd64 go list -mod=vendor -deps ./...)
    for dependency in $dependencies; do
        case "$dependency" in
            net|net/*|os/exec|plugin|*/rpc|*/rpc/*|*/vault|*/vault/*|*/redis|*/redis/*)
                printf 'Network or process-launch dependency in %s runtime graph: %s\n' \
                    "$target_os" "$dependency" >&2
                exit 1
                ;;
        esac
    done
    GOOS="$target_os" GOARCH=amd64 go build -mod=vendor ./...
done

# Run tests for the host, regardless of inherited cross-compilation settings.
GOOS=$(go env GOHOSTOS)
GOARCH=$(go env GOHOSTARCH)
export GOOS GOARCH

go test -mod=vendor ./... -count=1
go vet -mod=vendor ./...
printf 'PASS: dependency checks, Windows/Linux builds, host tests and vet.\n'
