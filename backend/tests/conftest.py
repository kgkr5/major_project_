"""
Shared pytest fixtures for AgentShield backend tests.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

# Ensure project root is on path
_root = Path(__file__).resolve().parents[2]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# Use in-memory SQLite for tests
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MODEL_PATH", "models/agentshield_rf_test.pkl")


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    """Provide an async database session for tests."""
    from backend.database.database import AsyncSessionLocal, init_db, engine, Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_alert_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample_alert.json"


@pytest.fixture
def eve_sample_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "eve_sample.json"


@pytest.fixture
def sample_77_features():
    """Return a valid 77-element feature list of zeros."""
    return [0.0] * 77


@pytest.fixture
def sample_feature_dict():
    """Return a valid feature dict with zero values."""
    from ml.feature_schema import FEATURE_NAMES
    return {name: 0.0 for name in FEATURE_NAMES}
