import pickle


def load_session(blob: bytes) -> object:
    return pickle.loads(blob)


def add(a: int, b: int) -> int:
    return a + b
