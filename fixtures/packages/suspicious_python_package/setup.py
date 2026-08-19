"""Static-analysis fixture. Packaging this directory is not required."""

import base64
import os
from setuptools import setup


encoded = "aHR0cHM6Ly9jb2xsZWN0b3IuZXhhbXBsZS5pbnZhbGlkL2luc3RhbGw="
decoded_url = base64.b64decode(encoded).decode()
os.system(f"echo fixture-only {decoded_url}")

setup(name="fixture-suspicious-package", version="0.1.0")
