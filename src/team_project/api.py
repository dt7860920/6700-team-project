from fastapi import FastAPI

from team_project.config import settings
from team_project.models import (
    Alias_To_Cat,
    Recommendation,
    RecommendationRequest,
    RecommendationResponse,
)
from team_project.fakemodel import model

app = FastAPI(title=settings.app_name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.post("/predict", response_model=RecommendationResponse)
def predict(req: RecommendationRequest) -> RecommendationResponse:
    predicted_categories = model.predict([c.value for c in req.interests])
    predicted_categories = predicted_categories[: req.max_results]
    recommendations: list[Recommendation] = []
    for item in predicted_categories:
        key = item.strip().lower()
        category = Alias_To_Cat.get(key)
        if category is None:
            continue
        recommendations.append(Recommendation(name=f"Sample {category.value}", category=category, distance_miles=0.5,))
    return RecommendationResponse(user_id=req.user_id, recommendations=recommendations,)

#Keeping old Code for reference
# def predict(req: RecommendationRequest) -> RecommendationResponse:
#     fake_results = [
#         Recommendation(name=f"Sample {c.value}", category=c, distance_miles=0.5)
#         for c in req.interests[: req.max_results]
#     ]
#     return RecommendationResponse(user_id=req.user_id, recommendations=fake_results)
