import pytest

from team_project.config import Settings


def test_invalid_env_raises():
    """
    Checks if the code throws an error as expected.
    """
    with pytest.raises(ValueError):
        Settings(environment="not_a_real_env")
