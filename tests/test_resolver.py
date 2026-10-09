import socket
import threading

import dns.flags
import dns.message
import dns.reversename
import dns.rrset
import pytest

from dog import cli
from dog.config import Config
from dog.resolver import UdpResolver, addresses


class FakeServer:
    """A one-socket UDP DNS server on localhost that records the queries it sees."""

    def __init__(self, truncate=False, drop_first=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries = []
        self.truncate = truncate
        self.drop_first = drop_first
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            query = dns.message.from_wire(data)
            self.queries.append(query)
            if len(self.queries) <= self.drop_first:
                continue
            response = dns.message.make_response(query, our_payload=1232)
            response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "192.0.2.1"))
            if self.truncate:
                response.flags |= dns.flags.TC
            self.sock.sendto(response.to_wire(), addr)

    def close(self):
        self.sock.close()


@pytest.fixture
def server(request):
    srv = FakeServer(**getattr(request, "param", {}))
    yield srv
    srv.close()


def make_resolver(server, **kwargs):
    cfg = Config(port=server.port, timeout=0.5, **kwargs)
    return UdpResolver(cfg, ["127.0.0.1"])


def test_query_advertises_edns_payload(server):
    result = make_resolver(server, payload=4096).query("example.com", "A")

    assert result.status == "NOERROR"
    assert [r.value for r in result.records] == ["192.0.2.1"]
    assert server.queries[0].edns == 0
    assert server.queries[0].payload == 4096
    assert result.edns is not None and result.edns.server_payload == 1232
    assert result.size > 0


def test_dnssec_sets_do_bit(server):
    make_resolver(server, dnssec=True).query("example.com", "A")
    assert server.queries[0].ednsflags & dns.flags.DO


def test_no_edns(server):
    result = make_resolver(server, edns=False).query("example.com", "A")
    assert server.queries[0].edns == -1
    assert result.edns is None


@pytest.mark.parametrize("server", [{"truncate": True}], indirect=True)
def test_truncation_is_reported_not_retried(server):
    result = make_resolver(server).query("example.com", "A")
    assert result.truncated
    assert "truncated" in result.error
    assert len(server.queries) == 1


@pytest.mark.parametrize("server", [{"drop_first": 1}], indirect=True)
def test_retries_after_timeout(server):
    result = make_resolver(server, retries=1).query("example.com", "A")
    assert result.status == "NOERROR"
    assert len(server.queries) == 2


FE80_1_PTR = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."


@pytest.mark.parametrize(
    "ip, qname",
    [
        ("fe80::1", FE80_1_PTR),
        # The scope (%lo) only picks an interface; the address, and so its PTR name, is the same.
        ("fe80::1%lo", FE80_1_PTR),
        ("fe80::1%en0", FE80_1_PTR),
        ("fe80::1%1", FE80_1_PTR),
        ("2001:db8::1%eth0", dns.reversename.from_address("2001:db8::1").to_text()),
        ("192.0.2.1", "1.2.0.192.in-addr.arpa."),
    ],
)
def test_reverse_strips_ipv6_scope(server, ip, qname):
    result = make_resolver(server).reverse(ip)
    assert result.qname == qname
    assert server.queries[0].question[0].name.to_text() == qname


def test_main_reverse_scoped_ipv6(server, tmp_path, monkeypatch, capsys):
    for var in ("IPINFO_TOKEN", "DOG_NAMESERVERS", "DOG_PAYLOAD"):
        monkeypatch.delenv(var, raising=False)
    argv = ["--config", str(tmp_path / "nope.toml"), "--port", str(server.port), "--timeout", "0.5", "fe80::1%lo", "@127.0.0.1"]

    assert cli.main(argv) == 0

    out = capsys.readouterr().out
    assert out.startswith("; <<>> dog <<>> fe80::1%lo\n")  # the target is shown as given
    assert f";; {FE80_1_PTR} PTR: NOERROR" in out
    assert "fe80::1%lo  bogon" in out  # ipinfo marks it locally; no request is made


def test_addresses_deduplicates():
    from dog.resolver import QueryResult, Record

    results = [
        QueryResult("a.", "A", "NOERROR", records=[Record("a.", 1, "CNAME", "b."), Record("b.", 1, "A", "192.0.2.1")]),
        QueryResult("a.", "A", "NOERROR", records=[Record("b.", 1, "A", "192.0.2.1"), Record("b.", 1, "AAAA", "2001:db8::1")]),
    ]
    assert addresses(results) == ["192.0.2.1", "2001:db8::1"]
