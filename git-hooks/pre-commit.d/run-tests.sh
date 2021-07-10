#!/usr/bin/env bash
set -e -o pipefail
echo $@
docker-compose run --rm oauthsrv go test -timeout 30s ./...
