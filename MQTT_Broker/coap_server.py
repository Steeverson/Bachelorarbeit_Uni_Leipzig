import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 5683))
while True:
    data, addr = sock.recvfrom(1024)
    if not data:
        continue
    mid = data[2:4] 
    response = bytes([0x60, 0x45]) + mid + b'\xffOK'
    sock.sendto(response, addr)
