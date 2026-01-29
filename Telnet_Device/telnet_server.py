import socket, threading

BANNER = b"Welcome to SAMPLE Telnet Device\r\n"
LOGIN_PROMPT = b"login: "
PASS_PROMPT  = b"Password: "
OK_MSG       = b"\r\nLogin successful.\r\n$ "
FAIL_MSG     = b"\r\nLogin incorrect\r\n"

def recv_line(conn, maxlen=128, timeout=10):
    conn.settimeout(timeout)
    buf = b""
    while len(buf) < maxlen:
        try:
            b = conn.recv(1)
            if not b:
                break
            if b == b"\xff":
                conn.recv(2)
                continue
            if b in (b"\n", b"\r"):
                conn.settimeout(0.01)
                try:
                    nxt = conn.recv(1)
                    if nxt not in (b"\n", b"\r"):
                        pass
                except Exception:
                    pass
                conn.settimeout(timeout)
                break
            buf += b
        except Exception:
            break
    return buf.strip()

def handle_client(conn, addr):
    try:
        conn.sendall(BANNER)
        conn.sendall(LOGIN_PROMPT)
        user = recv_line(conn)

        conn.sendall(PASS_PROMPT)
        pw = recv_line(conn)

        if user == b"root" and pw == b"admin":
            conn.sendall(OK_MSG)
            while True:
                conn.sendall(b"$ ")
                line = recv_line(conn, maxlen=256, timeout=120)
                if not line:
                    break
                if line.lower() in (b"exit", b"logout", b"quit"):
                    break
                conn.sendall(b"\r\n" + line + b"\r\n")
        else:
            conn.sendall(FAIL_MSG)
    except Exception:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()

def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", port))
    srv.listen(64)
    print(f"[TELNET DEVICE] Telnet server listening on :{port}")
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle_client, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    threading.Thread(target=serve, args=(23,), daemon=True).start()
    serve(2323)
