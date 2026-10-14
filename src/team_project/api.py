from fastapi import FastAPI

from team_project.config import settings
from team_project.models import (
    Alias_To_Cat,
    Recommendation,
    RecommendationRequest,
    RecommendationResponse,
)
from team_project.fakemodel import model
import asyncio

app = FastAPI(title=settings.app_name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.post("/predict", response_model=RecommendationResponse)
async def predict(req: RecommendationRequest) -> RecommendationResponse:
    predicted_categories = await asyncio.to_thread(model.predict, [c.value for c in req.interests], ) #Changed to use model.predict and c.value rather than predicting each value!
    predicted_categories = predicted_categories[: req.max_results]
    recommendations: list[Recommendation] = []
    for item in predicted_categories:
        key = item.strip().lower()
        category = Alias_To_Cat.get(key)
        if category is None:
            continue
        recommendations.append(Recommendation(name=f"Sample {category.value}", category=category, distance_miles=0.5,))
    return RecommendationResponse(user_id=req.user_id, recommendations=recommendations,)
