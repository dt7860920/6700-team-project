import asyncio

import httpx
import pytest
from httpx import ASGITransport

from team_project.api import app


@pytest.mark.asyncio
async def test_health_responds_during_slow_predict() -> None:
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        slow = asyncio.create_task(
            client.post("/predict", json={"user_id": "x", "interests": ["reading"]})
        )
        await asyncio.sleep(0.1)  # let the slow request start
        health = await client.get("/health")
        assert health.status_code == 200
        await slow
