#!/usr/bin/with-contenv bashio

set -e

bashio::log.info "[STAGE=BOOT] [RESULT=START] Starting Proxy от Бориса backend"
exec python3 /app/backend.py
