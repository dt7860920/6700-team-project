def test_health_returns_ok(client):
    """
    Verifies the health status code is 200

    Args:
    client - Test client used for this assignment

    Returns:
    {"status" : "ok"}
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_predict_returns_relevant_categories(client, grad_student_request):
    """
    Sending the grad student's sample categories to the prediction endpoint.
    Asserts that the response is 200 and the categories are a subset of the
    expected recommendation categories.

    Args:
    client - Test client used for this assignment
    grad_student_requests - grad student's user_id and interests.
    """
    response = client.post("/predict", json=grad_student_request.model_dump())
    assert response.status_code == 200
    categories = {r["category"] for r in response.json()["recommendations"]}
    assert categories.issubset({"reading", "exercise", "exploring"})


def test_predict_respects_max_results(client, pentagon_worker_request):
    """
    Sending the pentagon employee's sample categories to the prediction
    endpoint. Asserts that the response is 200 and the number of
    recommendations does not exceed the request max.

    Args:
    client - Test client used for this assignment
    pentagon_worker_requests - pentagon employee's user_id and interests.
    """
    response = client.post("/predict", json=pentagon_worker_request.model_dump())
    body = response.json()
    assert len(body["recommendations"]) <= pentagon_worker_request.max_results
