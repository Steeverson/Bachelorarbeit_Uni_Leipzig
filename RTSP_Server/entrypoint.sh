#!/usr/bin/env bash
set -euo pipefail

MTX_BIN="${MTX_BIN:-/usr/local/bin/mediamtx}"
CFG="${MEDIAMTX_CONFIG:-/etc/mediamtx.json}"

MAIN_PORT="${RTSP_PORT_MAIN:-8554}"     # nativer MediaMTX RTSP-Port
COMPAT_PORT="${RTSP_PORT_COMPAT:-554}"  # Kompatibilitäts-Port (socat-Forward -> MAIN_PORT)

# Autopublisher: hält /stream1 dauerhaft aktiv, damit ffmpeg-Leseangriffe (DESCRIBE/SETUP) funktionieren
AUTO_PUBLISH="${AUTO_PUBLISH:-1}"
PUBLISH_PATH="${PUBLISH_PATH:-stream1}" # WICHTIG: stream1 bleibt fürs Auto-Publish reserviert
PUBLISH_URL="rtsp://127.0.0.1:${MAIN_PORT}/${PUBLISH_PATH}"

# ffmpeg-Quelle/Codecs (Testbild + Ton)
FF_VSRC="${FF_VSRC:-testsrc2=size=1280x720:rate=25}"
FF_ASRC="${FF_ASRC:-sine=frequency=1000}"
FF_VOPTS="${FF_VOPTS:--c:v libx264 -preset veryfast -tune zerolatency -pix_fmt yuv420p -b:v 2M}"
FF_AOPTS="${FF_AOPTS:--c:a aac -ar 44100 -b:a 128k}"

_pids=()
cleanup() {
  echo "[RTSP SERVER] Caught signal, shutting down..."
  for p in "${_pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait || true
}
trap cleanup TERM INT

wait_port() {
  local host="$1" port="$2" tries="${3:-60}" delay="${4:-0.5}"
  for i in $(seq 1 "$tries"); do
    if timeout 1 bash -lc "</dev/tcp/${host}/${port}" 2>/dev/null; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

echo "[RTSP SERVER] Starting MediaMTX on :${MAIN_PORT} with config ${CFG}..."
"${MTX_BIN}" "${CFG}" &
_pids+=($!)

echo "[RTSP SERVER] Waiting for MediaMTX to accept TCP on 127.0.0.1:${MAIN_PORT}..."
if ! wait_port 127.0.0.1 "${MAIN_PORT}" 120 0.5; then
  echo "[RTSP SERVER] MediaMTX did not open :${MAIN_PORT} in time. Aborting."
  exit 1
fi
echo "[RTSP SERVER] MediaMTX ready."

echo "[RTSP SERVER] Starting TCP forwarder ${COMPAT_PORT} -> ${MAIN_PORT} (socat)..."
socat -d -d TCP-LISTEN:${COMPAT_PORT},fork,reuseaddr TCP:127.0.0.1:${MAIN_PORT} &
_pids+=($!)

if [[ "${AUTO_PUBLISH}" == "1" ]]; then
  echo "[RTSP SERVER] Auto-publish enabled: pushing testpattern to ${PUBLISH_URL}"
  (
    while true; do
      wait_port 127.0.0.1 "${MAIN_PORT}" 20 0.5 || true
      ffmpeg -hide_banner -loglevel error -re \
        -f lavfi -i "${FF_VSRC}" \
        -f lavfi -i "${FF_ASRC}" \
        ${FF_VOPTS} ${FF_AOPTS} \
        -f rtsp -rtsp_transport tcp "${PUBLISH_URL}" || true
      echo "[RTSP SERVER] ffmpeg publisher exited; restarting in 2s..."
      sleep 2
    done
  ) &
  _pids+=($!)
else
  echo "[RTSP SERVER] Auto-publish disabled; external publishers can use rtsp://<host>:${MAIN_PORT}/stream"
fi

echo "[RTSP SERVER] Runtime ready."

wait