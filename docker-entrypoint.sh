#!/bin/sh
set -eu
if [ ! -f "${PAG_DATA_DIR:-/data}/master.key" ] || [ ! -f "${PAG_DATA_DIR:-/data}/admin.token" ]; then
  echo "Initializing PAG data directory..."
  node ./bin/pag.js init
fi
exec node ./bin/pag.js serve --host "${PAG_HOST:-0.0.0.0}" --port "${PAG_PORT:-8787}"
