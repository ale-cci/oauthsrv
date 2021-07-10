#!/usr/bin/env bash
set -e -o pipefail

go_files=`git diff --cached --name-only HEAD | { grep -e '\.go$' || true; }`

[[ -z "$go_files" ]] && echo "Skip" && exit 0
docker-compose run --rm oauthsrv go test -timeout 30s ./...
