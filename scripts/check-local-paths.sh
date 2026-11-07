#!/bin/sh
# Fails if a tracked file contains a path from someone's home directory.
set -eu
cd "$(dirname "$0")/.."
if git ls-files -z | grep -zv '^scripts/check-local-paths.sh$' | xargs -0 grep -nIE '(/home/[a-z_][a-z0-9_-]*/|/Users/[A-Za-z][A-Za-z0-9_-]*/|[A-Z]:\\Users\\)' ; then
  echo "local paths found in tracked files" >&2
  exit 1
fi
echo "no local paths found"
