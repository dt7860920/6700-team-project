import asyncio

from fastapi import FastAPI

from team_project.config import settings
from team_project.model_client import model_client
from team_project.models import (
    Alias_To_Cat,
    Recommendation,
    RecommendationRequest,
    RecommendationResponse,
)

app = FastAPI(title=settings.app_name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/predict", response_model=RecommendationResponse)
async def predict(req: RecommendationRequest) -> RecommendationResponse:
    # Offload the blocking model call to a worker thread so the event loop
    # stays responsive under concurrent requests.
    predicted = await asyncio.to_thread(
        model_client.predict, [c.value for c in req.interests]
    )
    predicted = predicted[: req.max_results]
    recommendations: list[Recommendation] = []
    for item in predicted:
        category = Alias_To_Cat.get(item.strip().lower())
        if category is None:
            continue
        recommendations.append(
            Recommendation(
                name=f"Sample {category.value}",
                category=category,
                distance_miles=0.5,
            )
        )
    return RecommendationResponse(user_id=req.user_id, recommendations=recommendations)
