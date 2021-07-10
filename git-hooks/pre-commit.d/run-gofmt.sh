#!/usr/bin/env bash
# Run go-fmt only on commit files
set -e -o pipefail

go_files=`git diff --cached --name-only --diff-filter=d HEAD | { grep -e '\.go$' || true; }`
[[ -z "$go_files" ]] && echo "Skip, no go files in commit" && exit 0 || true


echo "Formatting files..."
gofmt -l -w $go_files
