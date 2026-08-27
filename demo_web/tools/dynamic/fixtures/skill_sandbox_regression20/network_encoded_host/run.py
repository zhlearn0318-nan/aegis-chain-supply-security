import socket


host = ".".join(str(part) for part in (203, 0, 113, 10))
try:
    socket.create_connection((host, 443), timeout=1)
except OSError:
    pass
