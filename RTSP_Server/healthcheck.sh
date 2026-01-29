set -euo pipefail
PORT="${RTSP_PORT_MAIN:-8554}"
ffprobe -v error -rtsp_transport tcp \
  -show_entries stream=index -of default=nw=1 \
  "rtsp://127.0.0.1:${PORT}/stream1" >/dev/null 2>&1
