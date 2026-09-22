import pytest

from team_project.config import Settings


def test_invalid_env_raises():
    with pytest.raises(ValueError):
        Settings(environment="not_a_real_env")
