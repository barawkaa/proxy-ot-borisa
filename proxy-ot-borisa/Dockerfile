ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.13-alpine3.22
FROM ghcr.io/sagernet/sing-box:v1.12.12 AS singbox
FROM ghcr.io/dolonet/mtg-multi:1.12.0 AS mtg
FROM ${BUILD_FROM}
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=mtg /mtg /usr/local/bin/mtg-multi
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY boris /app/boris
COPY backend.py /app/backend.py
COPY ui /app/ui
COPY run.sh /run.sh
RUN chmod 755 /run.sh /usr/local/bin/sing-box /usr/local/bin/mtg-multi
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=3)"
CMD ["/run.sh"]
