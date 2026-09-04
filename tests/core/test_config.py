from reconforge.core.config import Config


def test_config_initialization():
    target = "example.com"
    modules = ["ports", "subdomains"]
    ports = ["80", "443"]
    wordlist = None
    output = None

    config = Config(target, modules, ports, wordlist, output)

    assert config.target.host == target
    assert len(config.modules) == 2
    assert config.ports == ports
    assert config.wordlist is None
    assert config.output is None
