from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl, threading, socket, urllib.parse as up, json, os

def get_self_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

SELF_IP = get_self_ip()

UPNP_RESPONSE = "\r\n".join([
    "HTTP/1.1 200 OK",
    "CACHE-CONTROL: max-age=120",
    "ST: upnp:rootdevice",
    "USN: uuid:DummyRouter::upnp:rootdevice",
    "EXT:",
    "SERVER: Python/3.11 UPnP/1.0 IoTDevice/1.0",
    f"LOCATION: http://{SELF_IP}:80/device.xml",
    "", ""
])

def parse_qs(path):
    parsed = up.urlparse(path)
    return parsed.path, dict(up.parse_qsl(parsed.query, keep_blank_values=True))

def read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    return handler.rfile.read(length) if length > 0 else b""

def ok(handler, body: bytes, ctype="text/plain"):
    handler.send_response(200, "OK")
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class RouterHandler(BaseHTTPRequestHandler):
    server_version = "VulnRouter/1.0"

    def do_GET(self):
        path, qs = parse_qs(self.path)

        if path == "/login.cgi" and "cli" in qs:
            return ok(self, b"Command executed via login.cgi (dummy)")

        if "images" in self.path:
            return ok(self, b"GPON router admin content (auth bypassed)")

        if path == "/cgi-bin/downloadFlile.cgi":
            return ok(self, b"downloadFlile.cgi response (dummy)")

        if path == "/goform/WriteFacMac":
            return ok(self, b"WriteFacMac applied (dummy)")

        if path == "/goform/AdvSetLanip":
            return ok(self, b"AdvSetLanip applied (dummy)")

        if "country=" in self.path:
            return ok(self, b"Country parameter applied (dummy)")

        if path == "/device.xml":
            xml = f"""<?xml version="1.0"?>
                    <root>
                    <device><friendlyName>DummyRouter</friendlyName><presentationURL>http://{SELF_IP}/</presentationURL></device>
                    </root>""".encode()
            return ok(self, xml, "application/xml")

        self.send_response(404); self.end_headers(); self.wfile.write(b"Not Found")

    def do_POST(self):
        path, qs = parse_qs(self.path)
        body = read_body(self)
        ctype = (self.headers.get("Content-Type") or "").lower()

        if path.startswith("/ubus"):
            return ok(self, b'{"jsonrpc":"2.0","result":"ok"}', "application/json")

        if path == "/ztp/cgi-bin/handler":
            return ok(self, b'{"status":"applied"}', "application/json")

        if path == "/HNAP1":
            return ok(self, b"<Envelope><Body>HNAP OK</Body></Envelope>", "text/xml")

        if path == "/cgi-bin/cstecgi.cgi":
            return ok(self, b"cstecgi.cgi applied (dummy)")

        if path == "/apply.cgi":
            return ok(self, b"apply.cgi OK (dummy)")

        if path == "/ping.ccp":
            return ok(self, b"ping OK (dummy)")

        if path.startswith("/cgi-bin/luci/"):
            return ok(self, b"luci country write OK (dummy)")

        if path == "/shell":
            return ok(self, b"MVPower /shell (dummy)", "text/plain")
            
        self.send_response(404); self.end_headers(); self.wfile.write(b"Not Found")

    def log_message(self, fmt, *args):
        return 


class TR064Handler(BaseHTTPRequestHandler):
    server_version = "TR064/1.0"

    def do_POST(self):
        body = read_body(self)
        self.send_response(200)
        self.send_header("Content-Type", "text/xml"); self.end_headers()
        self.wfile.write(b"<SOAP-ENV:Envelope><SOAP-ENV:Body>OK</SOAP-ENV:Body></SOAP-ENV:Envelope>")

    def do_GET(self):
        self.send_response(404); self.end_headers()

    def log_message(self, fmt, *args):
        return


def run_ssdp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 1900))
    print("[*] SSDP listener on 1900/UDP")
    while True:
        data, addr = sock.recvfrom(4096)
        if data and b"M-SEARCH" in data:
            sock.sendto(UPNP_RESPONSE.encode(), addr)



def run_http(port, ssl_ctx=None):
    httpd = HTTPServer(('', port), RouterHandler)
    if ssl_ctx:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"[VULNERABLE ROUTER] HTTPS server on :{port}")
    else:
        print(f"[VULNERABLE ROUTER] HTTP server on :{port}")
    httpd.serve_forever()

def run_tr064():
    HTTPServer(('', 7547), TR064Handler).serve_forever()

def main():
    threading.Thread(target=run_ssdp, daemon=True).start()

    threading.Thread(target=run_tr064, daemon=True).start()

    threading.Thread(target=run_http, args=(80, None), daemon=True).start()

    key = os.environ.get("SSL_KEY", "/etc/ssl/private/router.key")
    crt = os.environ.get("SSL_CRT", "/etc/ssl/certs/router.crt")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=crt, keyfile=key)
    run_http(443, ctx)

if __name__ == "__main__":
    print(f"[VULNERABLE ROUTER] Router services at http://{SELF_IP}:80 , https://{SELF_IP}:443 and :7547, :1900/UDP")
    main()
