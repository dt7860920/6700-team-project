import time

class FakeModel:
    def __init__(self):
        pass

    def predict(self, interests: list[str]) -> list[str]:
        time.sleep(1.5)
        return interests

model = FakeModel()