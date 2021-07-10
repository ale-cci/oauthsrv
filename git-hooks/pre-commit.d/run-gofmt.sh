#!/usr/bin/env bash
# Run go-fmt only on commit files
set -e -o pipefail

go_files=`git diff --cached --name-only --diff-filter=d HEAD | { grep -e '\.go$' || true; }`
[[ -z "$go_files" ]] && echo "Skip, no go files in commit" && exit 0 || true

exec 5>&1
output=`gofmt -l -w "$go_files" | tee /dev/fd/5`
[[ -z "$output" ]]
