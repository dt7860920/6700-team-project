from fastapi import FastAPI

from team_project.config import settings
from team_project.models import (
    Recommendation,
    RecommendationRequest,
    RecommendationResponse,
)

app = FastAPI(title=settings.app_name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.post("/predict", response_model=RecommendationResponse)
def predict(req: RecommendationRequest) -> RecommendationResponse:
    fake_results = [
        Recommendation(name=f"Sample {c.value}", category=c, distance_miles=0.5)
        for c in req.interests[: req.max_results]
    ]
    return RecommendationResponse(user_id=req.user_id, recommendations=fake_results)
