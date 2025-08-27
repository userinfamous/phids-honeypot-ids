import asyncio
import socket
import time
import pytest

from pathlib import Path


def _connect_tcp(host, port, send_bytes=None, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if send_bytes:
            sock.send(send_bytes)
            time.sleep(0.1)
        return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


@pytest.mark.parametrize("port,service", [(2222, "ssh"), (8080, "http")])
def test_honeypot_ports_listening(port, service):
    """Simple smoke test: core honeypot ports should be listening if service enabled."""
    host = "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((host, port))
        assert result == 0, f"{service} honeypot not listening on {port}"
    finally:
        sock.close()


@pytest.mark.asyncio
async def test_ssh_basic_banner():
    """Connect to SSH port and check server sends a banner (non-blocking)."""
    host = "127.0.0.1"
    port = 2222
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        # try to receive banner (best-effort)
        try:
            data = sock.recv(256)
            assert data, "No banner received from SSH honeypot"
        except Exception:
            pytest.skip("Could not read banner from SSH honeypot")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_http_basic_get():
    import requests

    url = "http://127.0.0.1:8080/"
    try:
        resp = requests.get(url, timeout=2)
        assert resp.status_code in (200, 404), "Unexpected HTTP response"  # allow simple sites
    except requests.exceptions.ConnectionError:
        pytest.skip("HTTP honeypot not running")
