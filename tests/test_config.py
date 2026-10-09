from dataclasses import fields

import pytest

from dog import cli, config


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


def test_default_path_uses_xdg_config_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config.default_config_path() == tmp_path / "dog" / "config.toml"


@pytest.mark.parametrize("value", [None, "", "relative/dir", "."])
def test_default_path_ignores_unset_empty_or_relative_xdg(tmp_path, monkeypatch, value):
    # The XDG spec: empty means unset, and relative paths are invalid and ignored.
    monkeypatch.setenv("HOME", str(tmp_path))
    if value is None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    else:
        monkeypatch.setenv("XDG_CONFIG_HOME", value)

    path = config.default_config_path()

    assert path == tmp_path / ".config" / "dog" / "config.toml"
    assert path.is_absolute()


def test_build_reads_default_path_at_call_time(tmp_path, monkeypatch):
    (tmp_path / "dog").mkdir()
    (tmp_path / "dog" / "config.toml").write_text("payload = 1232\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config.build().payload == 1232


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


@pytest.mark.parametrize(
    "toml, option",
    [
        ('nameservers = "1.1.1.1"', "nameservers"),
        ('nameservers = ["dns.google"]', "nameservers"),
        ('nameservers = ["1.1.1.1", 53]', "nameservers"),
        ('nameservers = ["1.1.1.1", ""]', "nameservers"),
        ('payload = "4096"', "payload"),
        ("payload = 4096.0", "payload"),
        ("payload = true", "payload"),
        ('port = "53"', "port"),
        ("port = true", "port"),
        ("port = 53.0", "port"),
        ('edns = "false"', "edns"),
        ("edns = 0", "edns"),
        ('dnssec = "true"', "dnssec"),
        ('ipinfo = "no"', "ipinfo"),
        ('timeout = "3"', "timeout"),
        ("timeout = true", "timeout"),
        ("timeout = nan", "timeout"),
        ("timeout = inf", "timeout"),
        ('retries = "2"', "retries"),
        ("retries = false", "retries"),
        ("retries = 1.5", "retries"),
        ("ipinfo_token = 123", "ipinfo_token"),
        ("ipinfo_token = true", "ipinfo_token"),
    ],
)
def test_file_values_type_checked(tmp_path, toml, option):
    path = tmp_path / "config.toml"
    path.write_text(toml + "\n")
    with pytest.raises(config.ConfigError, match=rf"\b{option}\b"):
        config.build(path)


@pytest.mark.parametrize(
    "toml",
    [
        'nameservers = ["192.0.2.53", "2001:db8::53"]',
        "nameservers = []",
        "timeout = 2",  # an int is a fine float
        "edns = false",
        'ipinfo_token = "abc"',
    ],
)
def test_file_values_accepted(tmp_path, toml):
    path = tmp_path / "config.toml"
    path.write_text(toml + "\n")
    config.build(path)


@pytest.mark.parametrize("servers", ["dns.google", "1.1.1.1,dns.google", "1.1.1.1:53"])
def test_env_nameservers_must_be_ips(tmp_path, monkeypatch, servers):
    monkeypatch.setenv("DOG_NAMESERVERS", servers)
    with pytest.raises(config.ConfigError, match="nameservers"):
        config.build(tmp_path / "nope.toml")


@pytest.mark.parametrize(
    "overrides, option",
    [
        ({"nameservers": ["dns.google"]}, "nameservers"),
        ({"port": True}, "port"),
        ({"payload": "4096"}, "payload"),
        ({"edns": "false"}, "edns"),
        ({"timeout": float("nan")}, "timeout"),
        ({"retries": 1.0}, "retries"),
    ],
)
def test_override_values_type_checked(tmp_path, overrides, option):
    with pytest.raises(config.ConfigError, match=rf"\b{option}\b"):
        config.build(tmp_path / "nope.toml", overrides)


def test_every_config_field_has_a_type_check():
    # No field is left out: nameservers is checked as a list here, and its
    # entries are then checked as IP addresses separately in validate().
    # Equality also catches a stale table entry for a field that no longer exists.
    assert set(config.FIELD_TYPES) == {f.name for f in fields(config.Config)}


def test_validate_directly():
    with pytest.raises(config.ConfigError, match="port"):
        config.Config(port=True).validate()


@pytest.mark.parametrize(
    "contents",
    [
        b'nameservers = "1.1.1.1"\n',
        b'nameservers = ["dns.google"]\n',
        b'payload = "4096"\n',
        b'edns = "false"\n',
        b"port = true\n",
        b"timeout = nan\n",
        b"\xff\xfe not utf-8\n",
        b"payload = \n",
    ],
)
def test_main_reports_bad_config_without_traceback(tmp_path, capsys, contents):
    path = tmp_path / "config.toml"
    path.write_bytes(contents)
    assert cli.main(["--config", str(path), "--no-ipinfo", "example.com"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("dog: ") and "Traceback" not in err


def test_main_reports_unreadable_config(tmp_path, capsys):
    # A directory can't be read as a file.
    assert cli.main(["--config", str(tmp_path), "--no-ipinfo", "example.com"]) == 2
    assert capsys.readouterr().err.startswith("dog: ")


def test_main_reports_bad_env_without_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DOG_NAMESERVERS", "dns.google")
    assert cli.main(["--config", str(tmp_path / "nope.toml"), "--no-ipinfo", "example.com"]) == 2
    assert "nameservers" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--timeout", "nan"], ["--timeout", "inf"], ["--port", "0"]])
def test_main_reports_bad_flags(tmp_path, capsys, argv):
    assert cli.main(["--config", str(tmp_path / "nope.toml"), *argv, "--no-ipinfo", "example.com"]) == 2
    assert capsys.readouterr().err.startswith("dog: ")


@pytest.mark.parametrize("target", ["a..b", "x" * 64 + ".com", "x." * 130 + "com"])
def test_main_reports_bad_target(tmp_path, capsys, target):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--config", str(tmp_path / "nope.toml"), "--no-ipinfo", target, "@192.0.2.1"])
    assert exc.value.code == 2
    assert "invalid" in capsys.readouterr().err
