FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SSL_KEY=/etc/ssl/private/router.key \
    SSL_CRT=/etc/ssl/certs/router.crt

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl openssl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ssl/private /etc/ssl/certs && \
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$SSL_KEY" -out "$SSL_CRT" -days 365 \
      -subj "/CN=vulnerable-router"

WORKDIR /app
COPY router_server.py /app/router_server.py

EXPOSE 80/tcp 443/tcp 7547/tcp 1900/udp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1/login.cgi?cli=ls" >/dev/null || exit 1

CMD ["python", "/app/router_server.py"]
