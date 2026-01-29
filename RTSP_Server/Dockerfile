FROM debian:bookworm-slim

ARG MEDIAMTX_VERSION=1.8.3
ENV DEBIAN_FRONTEND=noninteractive \
    AUTO_PUBLISH=1 \
    RTSP_PORT_MAIN=8554 \
    RTSP_PORT_COMPAT=554 \
    MEDIAMTX_CONFIG=/etc/mediamtx.json

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl ffmpeg socat iperf3  \
 && rm -rf /var/lib/apt/lists/*

RUN curl -L -o /tmp/mtx.tgz \
      https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_amd64.tar.gz \
 && tar -xzf /tmp/mtx.tgz -C /usr/local/bin mediamtx \
 && rm /tmp/mtx.tgz

COPY mediamtx.json /etc/mediamtx.json
COPY entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

EXPOSE 8554/tcp 554/tcp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
