"""Golden tests: pin the exact text and JSON output of main()."""

import json
from dataclasses import fields

import pytest

from dog import cli, config, ipinfo
from dog.resolver import EdnsInfo, QueryResult, Record

SERVER = "192.0.2.53"

RESULTS = {
    ("example.com", "A"): QueryResult(
        "example.com",
        "A",
        "NOERROR",
        server=SERVER,
        records=[
            Record("example.com.", 300, "A", "1.1.1.1"),
            Record("example.com.", 300, "A", "10.0.0.1"),
        ],
        size=72,
        edns=EdnsInfo(version=0, server_payload=1232, do=False),
    ),
    ("example.com", "AAAA"): QueryResult("example.com", "AAAA", "TIMEOUT", server=SERVER, error="query timed out"),
    ("example.com", "MX"): QueryResult(
        "example.com",
        "MX",
        "NOERROR",
        server=SERVER,
        records=[
            Record("example.com.", 3600, "MX", "10 mail.example.com."),
            Record("example.com.", 3600, "MX", "20 backup-mail.example.com."),
        ],
        truncated=True,
        size=512,
        edns=EdnsInfo(version=0, server_payload=4096, do=True),
        error="response truncated (TC set) and TCP fallback is disabled; the answer exceeds what 192.0.2.53 will send over UDP",
    ),
    ("1.1.1.1.in-addr.arpa.", "PTR"): QueryResult(
        "1.1.1.1.in-addr.arpa.",
        "PTR",
        "NOERROR",
        server=SERVER,
        records=[Record("1.1.1.1.in-addr.arpa.", 1800, "PTR", "one.one.one.one.")],
        size=78,
    ),
    ("nope.example", "A"): QueryResult("nope.example", "A", "TIMEOUT", error="no response"),
}

IPINFO = {
    "1.1.1.1": {"ip": "1.1.1.1", "org": "AS13335 Cloudflare, Inc.", "city": "Sydney", "country": "AU", "hostname": "one.one.one.one"},
    "10.0.0.1": {"ip": "10.0.0.1", "bogon": True},
    "8.8.8.8": {"ip": "8.8.8.8", "error": "HTTP 429"},
}


class FakeResolver:
    def __init__(self, config, nameservers):
        self.config = config
        self.nameservers = nameservers

    def query(self, qname, rdtype):
        return RESULTS[(qname, rdtype)]

    def reverse(self, ip):
        return RESULTS[(".".join(reversed(ip.split("."))) + ".in-addr.arpa.", "PTR")]


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    for var in ("IPINFO_TOKEN", "DOG_NAMESERVERS", "DOG_PAYLOAD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "UdpResolver", FakeResolver)
    monkeypatch.setattr(cli, "detect_nameservers", lambda: (["127.0.0.53"], "/etc/resolv.conf"))
    lookups = []

    def fake_lookup(ips, token=None, timeout=10.0):
        lookups.append(list(ips))
        return {ip: IPINFO[ip] for ip in ips if ip in IPINFO}

    monkeypatch.setattr(ipinfo, "lookup", fake_lookup)
    return lookups


@pytest.fixture
def run_main(tmp_path, capsys):
    def run(*argv, config=None):
        path = tmp_path / "config.toml"
        if config is not None:
            path.write_text(config)
        code = cli.main(["--config", str(path), *argv])
        return code, capsys.readouterr().out
    return run


FORWARD_TEXT = """\
; <<>> dog <<>> example.com
;; RESOLVERS: 192.0.2.53 (from command line)
;; TRANSPORT: UDP only, EDNS0 payload 4096

;; example.com A: NOERROR from 192.0.2.53, 72 bytes, server EDNS payload 1232
example.com.  300  IN  A  1.1.1.1
example.com.  300  IN  A  10.0.0.1

;; example.com AAAA: TIMEOUT from 192.0.2.53
;; WARNING: query timed out

;; IPINFO
1.1.1.1   AS13335 Cloudflare, Inc. | Sydney, AU | host one.one.one.one
10.0.0.1  bogon (private/reserved address)
"""


def test_forward_text(run_main, fakes):
    assert run_main("example.com", "@" + SERVER) == (0, FORWARD_TEXT)
    assert fakes == [["1.1.1.1", "10.0.0.1"]]


FORWARD_JSON = {
    "target": "example.com",
    "nameservers": ["192.0.2.53"],
    "nameserver_source": "command line",
    "transport": "udp",
    "edns_payload": 4096,
    "queries": [
        {
            "qname": "example.com",
            "rdtype": "A",
            "status": "NOERROR",
            "server": "192.0.2.53",
            "records": [
                {"name": "example.com.", "ttl": 300, "rdtype": "A", "value": "1.1.1.1"},
                {"name": "example.com.", "ttl": 300, "rdtype": "A", "value": "10.0.0.1"},
            ],
            "truncated": False,
            "size": 72,
            "edns": {"version": 0, "server_payload": 1232, "do": False},
            "error": None,
        },
        {
            "qname": "example.com",
            "rdtype": "AAAA",
            "status": "TIMEOUT",
            "server": "192.0.2.53",
            "records": [],
            "truncated": False,
            "size": None,
            "edns": None,
            "error": "query timed out",
        },
    ],
    "ipinfo": {
        "1.1.1.1": {"ip": "1.1.1.1", "org": "AS13335 Cloudflare, Inc.", "city": "Sydney", "country": "AU", "hostname": "one.one.one.one"},
        "10.0.0.1": {"ip": "10.0.0.1", "bogon": True},
    },
}


def test_forward_json(run_main):
    code, out = run_main("example.com", "@" + SERVER, "--json")
    assert code == 0
    assert out == json.dumps(FORWARD_JSON, indent=2) + "\n"  # exact bytes, including key order


TRUNCATED_TEXT = """\
; <<>> dog <<>> example.com
;; RESOLVERS: 127.0.0.53 (from /etc/resolv.conf)
;; TRANSPORT: UDP only, EDNS0 payload 4096

;; example.com MX: NOERROR from 192.0.2.53, 512 bytes, server EDNS payload 4096, DO
;; WARNING: response truncated (TC set) and TCP fallback is disabled; the answer exceeds what 192.0.2.53 will send over UDP
example.com.  3600  IN  MX  10 mail.example.com.
example.com.  3600  IN  MX  20 backup-mail.example.com.
"""


def test_truncated_text_with_detected_resolver(run_main, fakes):
    assert run_main("example.com", "mx") == (0, TRUNCATED_TEXT)
    assert fakes == [[]]  # no addresses, but ipinfo is still consulted


REVERSE_TEXT = """\
; <<>> dog <<>> 1.1.1.1
;; RESOLVERS: 192.0.2.53, 192.0.2.54 (from config)
;; TRANSPORT: UDP only, no EDNS

;; 1.1.1.1.in-addr.arpa. PTR: NOERROR from 192.0.2.53, 78 bytes
1.1.1.1.in-addr.arpa.  1800  IN  PTR  one.one.one.one.
"""


def test_reverse_text_no_edns_no_ipinfo(run_main, fakes):
    config = 'nameservers = ["192.0.2.53", "192.0.2.54"]\n'
    assert run_main("1.1.1.1", "--no-edns", "--no-ipinfo", config=config) == (0, REVERSE_TEXT)
    assert fakes == []


def test_reverse_json_no_edns(run_main):
    code, out = run_main("1.1.1.1", "@" + SERVER, "--no-edns", "--json")
    assert code == 0
    report = json.loads(out)
    assert report["edns_payload"] is None
    assert report["ipinfo"] == {"1.1.1.1": IPINFO["1.1.1.1"]}
    assert [q["rdtype"] for q in report["queries"]] == ["PTR"]


FAILED_TEXT = """\
; <<>> dog <<>> nope.example
;; RESOLVERS: 192.0.2.53 (from command line)
;; TRANSPORT: UDP only, EDNS0 payload 1232

;; nope.example A: TIMEOUT
;; WARNING: no response
"""


def test_all_failed_exits_1(run_main):
    assert run_main("nope.example", "A", "@" + SERVER, "--payload", "1232") == (1, FAILED_TEXT)


def test_all_failed_json(run_main):
    code, out = run_main("nope.example", "A", "@" + SERVER, "--json")
    assert code == 1
    assert json.loads(out)["queries"] == [
        {
            "qname": "nope.example",
            "rdtype": "A",
            "status": "TIMEOUT",
            "server": None,
            "records": [],
            "truncated": False,
            "size": None,
            "edns": None,
            "error": "no response",
        }
    ]


def test_ipinfo_error_text(run_main, monkeypatch):
    result = QueryResult(
        "dns.example", "A", "NOERROR", server=SERVER, records=[Record("dns.example.", 60, "A", "8.8.8.8")], size=45
    )
    monkeypatch.setitem(RESULTS, ("dns.example", "A"), result)
    code, out = run_main("dns.example", "A", "@" + SERVER)
    assert code == 0
    assert out.endswith(";; IPINFO\n8.8.8.8  error: HTTP 429\n")


@pytest.fixture
def built(monkeypatch):
    """Capture the Config that main() builds."""
    configs = []
    real_build = cli.configmod.build

    def build(path=None, overrides=None):
        configs.append(real_build(path, overrides))
        return configs[-1]

    monkeypatch.setattr(cli.configmod, "build", build)
    return configs


@pytest.mark.parametrize(
    "flags, option, value",
    [
        (["--payload", "1232"], "payload", 1232),
        (["--no-edns"], "edns", False),
        (["--dnssec"], "dnssec", True),
        (["--port", "5353"], "port", 5353),
        (["--timeout", "1.5"], "timeout", 1.5),
        (["--retries", "0"], "retries", 0),
        (["--no-ipinfo"], "ipinfo", False),
        (["--token", "abc"], "ipinfo_token", "abc"),
    ],
)
def test_flags_override_config(run_main, built, flags, option, value):
    # The file sets a different value for each option, so the flag must win.
    config = 'payload = 4000\nedns = true\ndnssec = false\nport = 53\ntimeout = 9.0\nretries = 5\nipinfo = true\nipinfo_token = "file"\n'
    run_main("--show-resolver", *flags, config=config)
    assert getattr(built[0], option) == value


@pytest.mark.parametrize(
    "argv",
    [
        ["1.1.1.1", "MX", "@192.0.2.53", "--json", "--payload", "1232"],
        ["--json", "--payload", "1232", "1.1.1.1", "MX", "@192.0.2.53"],
        # Positionals after options: rejected by parse_args() before Python 3.12.
        ["1.1.1.1", "--json", "@192.0.2.53", "MX", "--payload", "1232"],
        ["1.1.1.1", "--json", "--payload", "1232", "MX", "@192.0.2.53"],
        ["--json", "1.1.1.1", "--payload", "1232", "@192.0.2.53", "mx"],
    ],
)
def test_options_and_positionals_can_be_mixed(argv):
    args = cli.parse_args(argv)
    assert (args.target, args.types, args.servers, args.json, args.payload) == ("1.1.1.1", ["MX"], ["192.0.2.53"], True, 1232)


@pytest.mark.parametrize(
    "argv, servers",
    [
        (["example.com"], []),
        (["example.com", "@192.0.2.53"], ["192.0.2.53"]),
        (["example.com", "@192.0.2.53", "@192.0.2.54"], ["192.0.2.53", "192.0.2.54"]),
        (["example.com", "@192.0.2.54", "MX", "--json", "@2001:db8::53"], ["192.0.2.54", "2001:db8::53"]),
    ],
)
def test_every_at_server_is_kept_in_order(argv, servers):
    assert cli.parse_args(argv).servers == servers


def test_main_queries_every_at_server(run_main, monkeypatch):
    seen = []

    class Recording(FakeResolver):
        def __init__(self, config, nameservers):
            super().__init__(config, nameservers)
            seen.append(nameservers)

    monkeypatch.setattr(cli, "UdpResolver", Recording)
    code, out = run_main("example.com", "@192.0.2.53", "@192.0.2.54", "--no-ipinfo", config='nameservers = ["192.0.2.9"]\n')
    assert code == 0
    assert seen == [["192.0.2.53", "192.0.2.54"]]  # both, in order, and they replace the config's list
    assert ";; RESOLVERS: 192.0.2.53, 192.0.2.54 (from command line)\n" in out


def test_show_resolver_lists_every_at_server(run_main):
    assert run_main("--show-resolver", "x", "@192.0.2.53", "@192.0.2.54") == (0, "192.0.2.53, 192.0.2.54 (from command line)\n")


@pytest.mark.parametrize(
    "argv, error",
    [
        (["example.com", "@192.0.2.53", "@dns.google"], "@server must be an IP address, got 'dns.google'"),
        (["example.com", "@dns.google", "@192.0.2.53"], "@server must be an IP address, got 'dns.google'"),
        # A bare @ used to be ignored, falling back to the system resolver.
        (["example.com", "@"], "@server must be an IP address, got ''"),
    ],
)
def test_bad_at_server_is_rejected(capsys, argv, error):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(argv)
    assert exc.value.code == 2
    assert error in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv, error",
    [
        (["example.com", "--json", "BOGUS"], "unknown record type: BOGUS"),
        (["example.com", "--json", "@dns.google"], "@server must be an IP address"),
        (["--json"], "a target is required"),
        (["example.com", "--json", "--nope"], "unrecognized arguments: --nope"),
    ],
)
def test_mixed_argument_errors(capsys, argv, error):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(argv)
    assert exc.value.code == 2
    assert error in capsys.readouterr().err


def test_every_config_field_has_a_flag():
    args = cli.parse_args(["example.com"])
    missing = {f.name for f in fields(config.Config)} - set(vars(args)) - {"nameservers"}
    assert not missing, f"Config fields with no CLI flag: {missing}"


def test_unset_flags_leave_config_alone(run_main, built):
    run_main("--show-resolver", config='payload = 4000\nnameservers = ["192.0.2.9"]\nipinfo_token = "file"\n')
    cfg = built[0]
    assert (cfg.payload, cfg.nameservers, cfg.ipinfo_token, cfg.edns, cfg.dnssec) == (4000, ["192.0.2.9"], "file", True, False)


@pytest.mark.parametrize(
    "argv, config, expected",
    [
        (["--show-resolver"], None, "127.0.0.53 (from /etc/resolv.conf)\n"),
        (["--show-resolver", "x", "@" + SERVER], None, "192.0.2.53 (from command line)\n"),
        (["--show-resolver"], 'nameservers = ["192.0.2.9"]\n', "192.0.2.9 (from config)\n"),
    ],
)
def test_show_resolver(run_main, argv, config, expected):
    assert run_main(*argv, config=config) == (0, expected)
