from enum import Enum
from pydantic import BaseModel, Field

class InterestCategory(str, Enum):
    reading = "reading"
    exercise = "exercise"
    exploring = "exploring"
    food = "food"
    drinking = "drinking"
    sports = "sports"

Interest_Aliases: dict[InterestCategory, set[str]] = {   
    InterestCategory.reading: {"reading", "bookstores", "libraries"},
    InterestCategory.exercise: {"running", "gym", "lifting weights"},
    InterestCategory.exploring:  {"sightseeing", "exploring", "travelling"},
    InterestCategory.food:  {"food", "restaurants", "dining"},
    InterestCategory.drinking: {"bar", "beer", "drinks"},
    InterestCategory.sports:  {"sports_bar", "football", "soccer", "baseball", "basketball", "sports"}
}

class RecommendationRequest(BaseModel):
    user_id: str
    interests: list[InterestCategory] = Field(min_length=1)
    location: str = "Pentagon City, VA"
    max_results: int = Field(default=5, ge=1, le=20)

class Recommendation(BaseModel):
    name: str
    category: InterestCategory
    distance_miles: float

class RecommendationResponse(BaseModel):
    user_id: str
    recommendations: list[Recommendation]
