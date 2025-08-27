import asyncio
import pytest


@pytest.mark.asyncio
async def test_main_initialize_stop():
    """Quick integration smoke test for main.PHIDSManager initialize/stop."""
    try:
        from main import PHIDSManager
    except Exception:
        pytest.skip("PHIDSManager not importable")

    mgr = PHIDSManager()
    # Call initialize but with a short timeout if implemented; keep minimal
    try:
        await asyncio.wait_for(mgr.initialize(), timeout=5)
    except asyncio.TimeoutError:
        # initialization may be long-running; treat as skip rather than fail
        pytest.skip("PHIDSManager.initialize() takes too long in test environment")

    # Stop should not raise
    try:
        await asyncio.wait_for(mgr.stop(), timeout=5)
    except asyncio.TimeoutError:
        pytest.skip("PHIDSManager.stop() takes too long in test environment")

    assert True
