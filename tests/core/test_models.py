from reconforge.core.models import Target


def test_target_creation_sets_host():
    target = Target("example.com")
    assert target.host == "example.com"
