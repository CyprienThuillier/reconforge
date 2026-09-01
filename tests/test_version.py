# tests/test_version.py
import reconforge


def test_package_is_importable():
    assert reconforge.__version__ == "0.1.0"
