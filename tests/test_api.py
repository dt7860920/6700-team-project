def test_health_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_predict_returns_relevant_categories(client, grad_student_request):
    response = client.post("/predict", json=grad_student_request.model_dump())
    assert response.status_code == 200
    categories = {r["category"] for r in response.json()["recommendations"]}
    assert categories.issubset({"reading", "exercise", "exploring"})


def test_predict_respects_max_results(client, pentagon_worker_request):
    response = client.post("/predict", json=pentagon_worker_request.model_dump())
    body = response.json()
    assert len(body["recommendations"]) <= pentagon_worker_request.max_results
