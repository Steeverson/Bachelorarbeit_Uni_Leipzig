from http.server import BaseHTTPRequestHandler, HTTPServer
import base64

DEFAULT_REALM = 'IoT Camera'

def parse_basic_auth(header: str):
    if not header:
        return None, None
    try:
        method, credentials = header.split(' ', 1)
        if method != 'Basic':
            return None, None
        decoded = base64.b64decode(credentials).decode('utf-8', errors='ignore')
        if ':' in decoded:
            user, pw = decoded.split(':', 1)
            return user, pw
    except Exception:
        pass
    return None, None

class CameraHandler(BaseHTTPRequestHandler):
    server_version = "InsecureCam/1.0"

    def _send_auth_401(self, message=b"Authentication required"):
        self.send_response(401, "Unauthorized")
        self.send_header('WWW-Authenticate', f'Basic realm="{DEFAULT_REALM}"')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(message)

    def _ok(self, body: bytes, ctype="text/plain"):
        self.send_response(200, "OK")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        if self.path.startswith("/system.ini"):
            fake_conf = (
                "[Network]\n"
                "user=admin\n"
                "password=admin\n"
                "rtsp_port=554\n"
                "onvif_enabled=1\n"
            ).encode()
            return self._ok(fake_conf, "text/plain")

        if self.path in ("/", "/admin", "/index.html"):
            user, pw = parse_basic_auth(self.headers.get('Authorization'))
            if user is None:
                return self._send_auth_401(b"Authentication required")
            if (user, pw) == ("admin", "admin"):
                return self._ok(b"Welcome, admin! (protected camera page)")
            return self._send_auth_401(b"Authentication failed")


        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        path = self.path
        body = self._read_body()

        if path == "/res.php":
            return self._ok(b"<ok>alarm processed</ok>", "text/xml")

        if path == "/cgi-bin/mft/wireless_mft":
            return self._ok(b'{"status":"applied"}', "application/json")

        if path == "/onvif/device_service":
            return self._ok(b"<s:Envelope><s:Body><tds:CreateUsersResponse>OK</tds:CreateUsersResponse></s:Body></s:Envelope>", "application/soap+xml")

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def log_message(self, fmt, *args):
        return

def run():
    HTTPServer(('', 80), CameraHandler).serve_forever()

if __name__ == "__main__":
    run()
