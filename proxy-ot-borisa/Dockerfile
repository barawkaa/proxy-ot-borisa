ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest

FROM ghcr.io/sagernet/sing-box:latest AS singbox
FROM nineseconds/mtg:2 AS mtg

FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=mtg /mtg /usr/local/bin/mtg

COPY run.sh /run.sh
COPY backend.py /app/backend.py
COPY ui /app/ui
COPY servers.example.json /defaults/servers.example.json

RUN sed -i 's/\r$//' /run.sh /app/backend.py && \
    chmod a+x /run.sh && \
    chmod a+x /usr/local/bin/sing-box && \
    chmod a+x /usr/local/bin/mtg

CMD ["/run.sh"]
