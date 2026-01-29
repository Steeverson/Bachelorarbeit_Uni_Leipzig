set -e

BRIDGE=br-smarthome
NETMASK=24  
GATEWAY=10.10.0.100 

IP_CAM=10.10.0.4
IP_MQTT=10.10.0.5
IP_TELNET=10.10.0.2
IP_ROUTER=10.10.0.3
IP_RTSP=10.10.0.6   


CONTAINERS="ip-camera mqtt-broker telnet-device vulnerable-router rtsp-server"  

IFACES="vscam vb_cam vmqtt vb_mqtt vtelnet vb_telnet vrouter vb_router vrtsp vb_rtsp" 

echo "[STARTUP] Removing all existing containers and interfaces"
sudo ip link delete $BRIDGE type bridge 2>/dev/null || true 
docker rm -f $CONTAINERS 2>/dev/null || true

for iface in $IFACES; do
    sudo ip link delete $iface 2>/dev/null || true
done

echo "[STARTUP] Creating Bridge: $BRIDGE..."
sudo ip link add $BRIDGE type bridge
sudo ip link set $BRIDGE up
sudo ip addr add ${GATEWAY}/$NETMASK dev $BRIDGE

echo "[STARTUP] Building docker containers"
docker build -t ip-camera ./IP_Camera
docker build -t mqtt-broker ./MQTT_Broker
docker build -t telnet-device ./Telnet_Device
docker build -t vulnerable-router ./Vulnerable_Router
docker build -t rtsp-server ./RTSP_Server

echo "[STARTUP] Starting containers without network"
docker run -d --name ip-camera --network none ip-camera
docker run -d --name mqtt-broker --network none mqtt-broker
docker run -d --name telnet-device --network none telnet-device
docker run -d --name vulnerable-router --network none vulnerable-router
docker run -d --name rtsp-server --network none rtsp-server


setup_veth() {
    iface_host=$1
    container_name=$2
    ip_address=$3
    iface_bridge=$4

    echo "[STARTUP] Creating veth for: $container_name ($ip_address)..."
    sudo ip link add $iface_host type veth peer name $iface_bridge 
    sudo ip link set $iface_bridge master $BRIDGE
    sudo ip link set $iface_bridge up

    PID=$(docker inspect -f '{{.State.Pid}}' $container_name)
    if [ "$PID" -eq 0 ]; then
        echo "[!] Fehler: Container $container_name läuft nicht."
        exit 1
    fi

    sudo ip link set $iface_host netns $PID
    sudo nsenter -t $PID -n ip link set $iface_host name eth0
    sudo nsenter -t $PID -n ip link set eth0 up
    sudo nsenter -t $PID -n ip addr add ${ip_address}/${NETMASK} dev eth0
    sudo nsenter -t $PID -n ip route add default via ${GATEWAY}
}

setup_veth vscam ip-camera $IP_CAM vb_cam
setup_veth vmqtt mqtt-broker $IP_MQTT vb_mqtt
setup_veth vtelnet telnet-device $IP_TELNET vb_telnet
setup_veth vrouter vulnerable-router $IP_ROUTER vb_router
setup_veth vrtsp rtsp-server $IP_RTSP vb_rtsp 

echo "[STARTUP] Isolated Smart-Home Testsetup created successfully"
echo "RTSP-Server can be reached by: rtsp://$IP_RTSP:554/stream"
echo "Start suricata with command: sudo suricata -i $BRIDGE"
