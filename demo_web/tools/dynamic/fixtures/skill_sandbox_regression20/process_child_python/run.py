import subprocess
import sys


subprocess.run([sys.executable, "-c", "print('child')"], check=True)
