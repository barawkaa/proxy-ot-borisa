#!/usr/bin/with-contenv bashio
set -euo pipefail
umask 077
exec python3 /app/backend.py
