ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:latest

ARG SING_BOX_IMAGE=ghcr.io/sagernet/sing-box:v1.12.12
ARG MTG_IMAGE=ghcr.io/dolonet/mtg-multi:latest

FROM ${SING_BOX_IMAGE} AS singbox
FROM ${MTG_IMAGE} AS mtg

FROM ${BUILD_FROM}

COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=mtg /mtg /usr/local/bin/mtg-multi

COPY run.sh /run.sh
COPY backend.py /app/backend.py
COPY ui /app/ui
COPY servers.example.json /defaults/servers.example.json

RUN sed -i 's/\r$//' /run.sh /app/backend.py && \
    chmod a+x /run.sh && \
    chmod a+x /usr/local/bin/sing-box && \
    chmod a+x /usr/local/bin/mtg-multi

CMD ["/run.sh"]
