import socket


try:
    socket.getaddrinfo("example.invalid", 443)
except OSError:
    pass
