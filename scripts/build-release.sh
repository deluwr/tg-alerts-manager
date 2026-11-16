#!/usr/bin/env bash
# Собирает релиз в dist/: tg-alerts-manager.tar.gz, его sha256 и install.sh.
#   bash scripts/build-release.sh [v1.2.3]   — без аргумента берёт версию из VERSION
set -euo pipefail
cd "$(dirname "$0")/.."

ver=$(tr -d '[:space:]' < VERSION)
if [ -n "${1:-}" ] && [ "${1#v}" != "$ver" ]; then
  echo "Тег $1 не совпадает с VERSION ($ver)" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2020-01-01 00:00Z' \
    --exclude='__pycache__' -czf dist/tg-alerts-manager.tar.gz VERSION install.sh README.md app
(cd dist && sha256sum tg-alerts-manager.tar.gz > tg-alerts-manager.tar.gz.sha256)
cp install.sh dist/install.sh
echo "dist/: tg-alerts-manager $ver"
