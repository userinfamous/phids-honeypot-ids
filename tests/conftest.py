import asyncio
import sys
from pathlib import Path
import pytest


# Ensure project root (python_final_project) is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def event_loop():
    """Provide an asyncio event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def db_manager():
    """Initialize DatabaseManager once per test session if available."""
    try:
        from src.core.database import DatabaseManager
    except Exception:
        pytest.skip("DatabaseManager not available")

    db = DatabaseManager()
    await db.initialize()
    yield db
    # Best-effort cleanup
    try:
        await db.close()
    except Exception:
        pass
