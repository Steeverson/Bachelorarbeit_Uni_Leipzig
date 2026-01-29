set -e

echo "[TEARDOWN] Starting teardown..."

CONTAINERS="ip-camera mqtt-broker telnet-device vulnerable-router rtsp-server"

BRIDGE=br-smarthome
IFACES="vscam vb_cam vmqtt vb_mqtt vtelnet vb_telnet vrouter vb_router vrtsp vb_rtsp"

echo "[TEARDOWN] Stopping and removing containers..."
docker rm -f $CONTAINERS 2>/dev/null || echo "Container has been removed already"

echo "[TEARDOWN] Removing veth interfaces..."
for iface in $IFACES; do
    sudo ip link delete $iface 2>/dev/null || true
done

echo "[TEARDOWN] Remobving Bridge $BRIDGE..."
sudo ip link delete $BRIDGE type bridge 2>/dev/null || echo "→ Bridge nicht vorhanden."

echo "[TEARDOWN] Isolated testsetup has been shut down successfully"
