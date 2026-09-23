from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class InterestCategory(StrEnum):
    reading = "reading"
    exercise = "exercise"
    exploring = "exploring"
    food = "food"
    drinking = "drinking"
    sports = "sports"


Interest_Aliases: dict[InterestCategory, set[str]] = {
    InterestCategory.reading: {"reading", "bookstores", "libraries"},
    InterestCategory.exercise: {"running", "gym", "lifting weights"},
    InterestCategory.exploring: {"sightseeing", "exploring", "travelling"},
    InterestCategory.food: {"food", "restaurants", "dining"},
    InterestCategory.drinking: {"bar", "beer", "drinks"},
    InterestCategory.sports: {
        "sports_bar",
        "football",
        "soccer",
        "baseball",
        "basketball",
        "sports",
    },
}

Alias_To_Cat: dict[str, InterestCategory] = {}
for category, aliases in Interest_Aliases.items():
    Alias_To_Cat[category.value] = category
    for alias in aliases:
        Alias_To_Cat[alias] = category


class RecommendationRequest(BaseModel):
    user_id: str
    interests: list[InterestCategory] = Field(min_length=1)
    location: str = "Pentagon City, VA"
    max_results: int = Field(default=5, ge=1, le=20)

    @field_validator("interests", mode="before")
    @classmethod
    def normalize_interest_aliases(cls, v):
        if not isinstance(v, list):
            return v
        normalized = []
        for item in v:
            if isinstance(item, InterestCategory):
                normalized.append(item)
                continue
            if isinstance(item, str):
                key = item.strip().lower()
                normalized.append(Alias_To_Cat.get(key, item))
                continue
            normalized.append(item)
        return normalized


class Recommendation(BaseModel):
    name: str
    category: InterestCategory
    distance_miles: float


class RecommendationResponse(BaseModel):
    user_id: str
    recommendations: list[Recommendation]
