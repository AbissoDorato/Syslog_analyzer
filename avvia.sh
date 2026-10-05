#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
    exec python3 app.py "$@"
elif command -v python >/dev/null 2>&1; then
    exec python app.py "$@"
else
    echo "Python 3.10 or newer is not installed or is not available in PATH." >&2
    exit 1
fi
