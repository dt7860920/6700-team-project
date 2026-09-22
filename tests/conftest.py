import pytest
from fastapi.testclient import TestClient

from team_project.api import app
from team_project.models import RecommendationRequest


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def grad_student_request():
    return RecommendationRequest(
        user_id="grad_student_1",
        interests=["reading", "running", "exploring"],
    )


@pytest.fixture
def pentagon_worker_request():
    return RecommendationRequest(
        user_id="pentagon_worker_1", interests=["food", "sports_bar"], max_results=3
    )
