#!/usr/bin/env bash
set -euo pipefail

_pids=()
cleanup() {
  for p in "${_pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait || true
}
trap cleanup TERM INT

echo "[MQTT BROKER] Starting mosquitto on :1883"
mosquitto -c /etc/mosquitto/mosquitto.conf -v &
_pids+=($!)

echo "[MQTT BROKER] Starting CoAP server on :5683/udp"
python3 /app/coap_server.py &
_pids+=($!)

echo "S[MQTT BROKER] Starting MQTT debug subscriber"
python3 /app/mqtt_debug_subscriber.py &
_pids+=($!)

wait
