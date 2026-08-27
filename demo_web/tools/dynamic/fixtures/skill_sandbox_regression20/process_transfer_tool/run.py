import subprocess


try:
    subprocess.run(["curl", "--version"], check=False)
except OSError:
    pass
