import os, sys, time
from datetime import datetime
import paho.mqtt.client as mqtt

BROKER_HOST = os.getenv("MQTT_HOST", "127.0.0.1")
BROKER_PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPICS = [
    ("acme/device/+/exec/server", 0),
    ("ACME/device/+/exec/server", 0),
]
LOGFILE = "/tmp/mqtt_debug_exec.log"

def log(msg: str):
    line = f"{datetime.utcnow().isoformat()}Z {msg}\n"
    sys.stdout.write(line); sys.stdout.flush()
    try:
        with open(LOGFILE, "a") as f:
            f.write(line)
    except Exception:
        pass

def on_connect(client, userdata, flags, rc, props=None):
    log(f"[connect] rc={rc}")
    for t, qos in TOPICS:
        client.subscribe(t, qos=qos)
        log(f"[subscribe] {t} qos={qos}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode("utf-8", errors="ignore")
    except Exception:
        payload = "<binary>"
    log(f"[msg] topic={msg.topic} payload={payload!r}")
    if payload.lower().startswith("debug "):
        cmd = payload[6:].strip()
        log(f"[exec-sim] would run: {cmd!r}")
        try:
            with open("/tmp/mqtt_exec_simulated", "a") as f:
                f.write(cmd + "\n")
        except Exception:
            pass

def main():
    client = mqtt.Client(client_id="debug-listener", clean_session=True, protocol=mqtt.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
    client.loop_forever()

if __name__ == "__main__":
    main()
