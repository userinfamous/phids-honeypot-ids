import pytest
import requests


BASE = "http://127.0.0.1:5000"


def _get(endpoint):
    try:
        return requests.get(f"{BASE}{endpoint}", timeout=2)
    except Exception:
        return None


def test_dashboard_root_accessible():
    resp = _get("")
    if resp is None:
        pytest.skip("Dashboard not running at http://127.0.0.1:5000")
    assert resp.status_code == 200


def test_api_stats_endpoint():
    resp = _get("/api/stats")
    if resp is None:
        pytest.skip("Dashboard API not accessible")
    j = resp.json()
    assert isinstance(j, dict)
    # core keys expected
    assert "total_connections" in j
    assert "total_alerts" in j


def test_recent_connections_endpoint():
    resp = _get("/api/recent-connections?limit=5")
    if resp is None:
        pytest.skip("Dashboard API not accessible")
    j = resp.json()
    assert "connections" in j
    assert isinstance(j["connections"], list)
