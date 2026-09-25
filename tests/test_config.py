import pytest

from dog import config


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("IPINFO_TOKEN", "DOG_NAMESERVERS", "DOG_PAYLOAD"):
        monkeypatch.delenv(var, raising=False)


def test_precedence(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('payload = 1232\nnameservers = ["192.0.2.53"]\ntimeout = 1.5\n')
    monkeypatch.setenv("DOG_PAYLOAD", "2048")

    cfg = config.build(path, {"timeout": 9.0, "retries": None})

    assert cfg.nameservers == ["192.0.2.53"]
    assert cfg.payload == 2048  # env beats file
    assert cfg.timeout == 9.0  # CLI beats file
    assert cfg.retries == 2  # None override leaves default


def test_missing_file_uses_defaults(tmp_path):
    cfg = config.build(tmp_path / "nope.toml")
    assert cfg.payload == 4096 and cfg.edns


def test_unknown_option_rejected(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("tcp = true\n")
    with pytest.raises(config.ConfigError, match="unknown option"):
        config.build(path)


@pytest.mark.parametrize("payload", [100, 70000])
def test_payload_bounds(tmp_path, payload):
    with pytest.raises(config.ConfigError, match="payload"):
        config.build(tmp_path / "nope.toml", {"payload": payload})
