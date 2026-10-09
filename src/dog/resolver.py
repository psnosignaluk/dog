"""UDP-only DNS client with EDNS(0).

Deliberately never uses TCP or DNS-over-HTTPS: if an answer doesn't fit in the
advertised EDNS buffer the response is reported as truncated rather than retried.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

from .config import Config

ADDRESS_TYPES = {"A", "AAAA"}
MAX_DATAGRAM = 65535


class NoResolverFound(Exception):
    pass


@dataclass
class Record:
    name: str
    ttl: int
    rdtype: str
    value: str


@dataclass
class EdnsInfo:
    version: int
    server_payload: int
    do: bool


@dataclass
class QueryResult:
    qname: str
    rdtype: str
    status: str
    server: str | None = None
    records: list[Record] = field(default_factory=list)
    truncated: bool = False
    size: int | None = None
    edns: EdnsInfo | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "NOERROR"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _scutil_nameservers() -> list[str]:
    """macOS: read the resolvers from the system configuration framework."""
    try:
        output = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    # The first "resolver #1" block is the default; take its nameservers in order.
    first_block = output.split("resolver #2", 1)[0]
    return re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", first_block)


def detect_nameservers() -> tuple[list[str], str]:
    """Find the local resolver(s). Returns (nameservers, where they came from)."""
    try:
        configured = dns.resolver.Resolver(configure=True).nameservers
    except dns.resolver.NoResolverConfiguration:
        configured = []
    servers = [str(s) for s in configured]
    if servers:
        return servers, "/etc/resolv.conf"
    if sys.platform == "darwin" and (servers := _scutil_nameservers()):
        return servers, "scutil --dns"
    raise NoResolverFound("could not find a local resolver; set nameservers in the config or use @server")


def _same_host(a: str, b: str) -> bool:
    return ipaddress.ip_address(a.split("%")[0]) == ipaddress.ip_address(b.split("%")[0])


def exchange(query: dns.message.Message, server: str, port: int, timeout: float) -> tuple[dns.message.Message, int]:
    """Send one query over UDP and wait for the matching response. Returns (response, wire size)."""
    family = socket.AF_INET6 if ipaddress.ip_address(server.split("%")[0]).version == 6 else socket.AF_INET
    wire = query.to_wire()
    deadline = time.monotonic() + timeout
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.sendto(wire, (server, port))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise dns.exception.Timeout
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(MAX_DATAGRAM)
            except TimeoutError:
                raise dns.exception.Timeout from None
            # Ignore stray datagrams from other hosts or for other queries.
            if not _same_host(addr[0], server):
                continue
            try:
                response = dns.message.from_wire(data, ignore_trailing=True)
            except dns.exception.DNSException:
                continue
            if query.is_response(response):
                return response, len(data)


class UdpResolver:
    def __init__(self, config: Config, nameservers: list[str]):
        if not nameservers:
            raise NoResolverFound("no nameservers configured")
        self.config = config
        self.nameservers = nameservers

    def _make_query(self, qname: str, rdtype: str, edns: bool) -> dns.message.Message:
        return dns.message.make_query(
            qname,
            rdtype,
            use_edns=0 if edns else False,
            payload=self.config.payload,
            want_dnssec=edns and self.config.dnssec,
        )

    def _attempt(self, qname: str, rdtype: str, server: str) -> QueryResult:
        use_edns = self.config.edns
        response, size = exchange(self._make_query(qname, rdtype, use_edns), server, self.config.port, self.config.timeout)
        # Some old middleboxes reject EDNS outright; retry once without it.
        if use_edns and response.rcode() == dns.rcode.FORMERR and response.edns < 0:
            use_edns = False
            response, size = exchange(self._make_query(qname, rdtype, False), server, self.config.port, self.config.timeout)
        payload = self.config.payload if use_edns else 512
        return self._to_result(qname, rdtype, server, response, size, payload)

    @staticmethod
    def _to_result(
        qname: str, rdtype: str, server: str, response: dns.message.Message, size: int, payload: int
    ) -> QueryResult:
        result = QueryResult(
            qname=qname,
            rdtype=rdtype,
            status=dns.rcode.to_text(response.rcode()),
            server=server,
            truncated=bool(response.flags & dns.flags.TC),
            size=size,
        )
        if response.edns >= 0:
            result.edns = EdnsInfo(
                version=response.edns,
                # The OPT record carries the payload size in its CLASS field.
                server_payload=int(response.payload),
                do=bool(response.ednsflags & dns.flags.DO),
            )
        for rrset in response.answer:
            rrtype = dns.rdatatype.to_text(rrset.rdtype)
            for rdata in rrset:
                result.records.append(Record(rrset.name.to_text(), rrset.ttl, rrtype, rdata.to_text()))
        if result.truncated:
            result.error = "response truncated (TC set) and TCP fallback is disabled"
            if payload < 4096:
                result.error += f"; try a larger --payload than {payload}"
            else:
                result.error += f"; the answer exceeds what {server} will send over UDP"
        return result

    def query(self, qname: str, rdtype: str) -> QueryResult:
        """Try each nameserver in turn, repeating the round `retries` times on timeout or SERVFAIL."""
        last = QueryResult(qname=qname, rdtype=rdtype, status="TIMEOUT", error="no response")
        for _ in range(self.config.retries + 1):
            for server in self.nameservers:
                try:
                    result = self._attempt(qname, rdtype, server)
                except dns.exception.Timeout:
                    last = QueryResult(qname, rdtype, "TIMEOUT", server=server, error="query timed out")
                    continue
                except OSError as exc:
                    last = QueryResult(qname, rdtype, "ERROR", server=server, error=str(exc))
                    continue
                if result.status in ("NOERROR", "NXDOMAIN"):
                    return result
                last = result
        return last

    def reverse(self, ip: str) -> QueryResult:
        # Drop any IPv6 scope (fe80::1%lo): it names an interface, not part of the
        # address, so the PTR name is the same, and from_address() rejects it.
        return self.query(dns.reversename.from_address(ip.split("%")[0]).to_text(), "PTR")


def addresses(results: list[QueryResult]) -> list[str]:
    """Unique A/AAAA addresses across all results, in first-seen order."""
    seen: dict[str, None] = {}
    for result in results:
        for record in result.records:
            if record.rdtype in ADDRESS_TYPES:
                seen.setdefault(record.value, None)
    return list(seen)
