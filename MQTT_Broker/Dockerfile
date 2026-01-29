FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      mosquitto mosquitto-clients python3 python3-paho-mqtt iproute2 curl \
  && rm -rf /var/lib/apt/lists/*


WORKDIR /app
COPY mosquitto.conf /etc/mosquitto/mosquitto.conf
COPY coap_server.py /app/coap_server.py
COPY mqtt_debug_subscriber.py /app/mqtt_debug_subscriber.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 1883/tcp 5683/udp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD mosquitto_pub -h 127.0.0.1 -t __health -m ok || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
