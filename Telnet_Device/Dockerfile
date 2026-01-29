FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-minimal python3-venv ca-certificates \
      nmap hping3 wget hydra netcat-openbsd iproute2 procps \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY telnet_server.py /app/telnet_server.py

EXPOSE 23/tcp 2323/tcp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD bash -lc 'echo | nc -w 2 127.0.0.1 23 | grep -qi "login:"'

CMD ["python3", "/app/telnet_server.py"]
