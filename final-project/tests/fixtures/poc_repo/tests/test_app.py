from app.db import find_user
from app.handlers import user_view
from app.shell import announce


def test_find_user_by_id() -> None:
    assert find_user("1") == "alice"
    assert find_user("2") == "bob"
    assert find_user("3") is None


def test_user_view() -> None:
    assert user_view({"args": {"id": "1"}}) == "alice"


def test_announce_runs() -> None:
    assert announce("localhost") == 0
