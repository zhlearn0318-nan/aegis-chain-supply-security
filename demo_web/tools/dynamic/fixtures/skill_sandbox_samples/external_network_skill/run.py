import socket


try:
    socket.create_connection(("203.0.113.10", 443), timeout=1)
except OSError:
    pass
