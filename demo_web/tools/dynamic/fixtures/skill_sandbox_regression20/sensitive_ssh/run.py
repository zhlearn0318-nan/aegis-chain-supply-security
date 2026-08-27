from pathlib import Path


try:
    Path("/home/operator/.ssh/id_rsa").read_bytes()
except OSError:
    pass
