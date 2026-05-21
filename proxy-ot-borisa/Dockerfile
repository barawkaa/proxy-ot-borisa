ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:latest
ARG SING_BOX_IMAGE=ghcr.io/sagernet/sing-box:v1.12.15
ARG MTG_MULTI_VERSION=v1.10.0

FROM ${SING_BOX_IMAGE} AS singbox

# mtg-multi is built from a fixed release tag instead of copying a mutable
# :latest image. This makes the add-on build reproducible enough for long-term
# local use. If you later want fully offline builds, put prebuilt binaries into
# bin/<arch>/ and adjust this stage to COPY them directly.
FROM golang:1.24-alpine AS mtg
ARG MTG_MULTI_VERSION
RUN apk add --no-cache git ca-certificates
RUN git clone --depth 1 --branch ${MTG_MULTI_VERSION} https://github.com/dolonet/mtg-multi.git /src
WORKDIR /src
RUN go build -trimpath -ldflags="-s -w" -o /mtg ./main.go

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
