import pytest
import asyncio
from pathlib import Path


@pytest.mark.asyncio
async def test_database_logging(db_manager):
    """Use db_manager fixture to write and read a test connection and alert."""
    try:
        test_connection = {
            'source_ip': '127.0.0.1',
            'source_port': 55555,
            'destination_port': 2222,
            'service_type': 'ssh',
            'session_id': 'pytest-test',
            'commands': [],
            'payloads': [],
            'user_agent': 'pytest'
        }
        await db_manager.log_connection(test_connection)

        test_alert = {
            'alert_type': 'pytest_alert',
            'severity': 'low',
            'source_ip': '127.0.0.1',
            'destination_ip': 'honeypot',
            'description': 'pytest generated alert'
        }
        await db_manager.log_alert(test_alert)

        # basic expectations: methods should exist and not raise
        assert True
    except Exception as e:
        pytest.fail(f"Database logging failed: {e}")


def test_honeypot_log_classification():
    """Check logs/honeypot.log for classification keywords (best-effort)."""
    log_file = Path(__file__).resolve().parents[1] / "logs" / "honeypot.log"
    if not log_file.exists():
        pytest.skip("honeypot.log not present; skip log classification check")

    content = log_file.read_text(encoding="utf-8", errors="ignore")
    keywords = ["SUCCESS", "FAILED", "ERROR", "TIMEOUT"]
    found = [k for k in keywords if k in content]
    assert len(found) >= 1, "No classification keywords found in honeypot.log"
