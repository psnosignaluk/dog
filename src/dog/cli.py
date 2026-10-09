"""Command-line interface: dig-style arguments, dig-style output, plus ipinfo."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

import dns.exception
import dns.name
import dns.rdatatype

from . import config as configmod
from . import ipinfo
from .ipinfo import Info
from .resolver import NoResolverFound, QueryResult, UdpResolver, addresses, detect_nameservers, is_ip

DEFAULT_TYPES = ["A", "AAAA"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dog",
        description="dig + ipinfo.io over UDP-only DNS with EDNS(0).",
        epilog="Examples: dog example.com | dog example.com MX TXT @1.1.1.1 | dog 8.8.8.8 --json",
    )
    parser.add_argument("target", nargs="?", help="domain name or IP address")
    parser.add_argument(
        "extra",
        nargs="*",
        metavar="TYPE|@SERVER",
        help=f"record types (default: {' '.join(DEFAULT_TYPES)}) and/or @nameserver, as with dig",
    )
    parser.add_argument("--config", type=Path, help=f"config file (default: {configmod.default_config_path()})")
    parser.add_argument("--payload", type=int, help="EDNS UDP payload size to advertise (default: 4096)")
    parser.add_argument("--no-edns", dest="edns", action="store_const", const=False, help="send plain DNS queries")
    parser.add_argument("--dnssec", action="store_const", const=True, help="set the EDNS DO bit")
    parser.add_argument("--port", type=int, help="nameserver port (default: 53)")
    parser.add_argument("--timeout", type=float, help="per-query timeout in seconds (default: 3)")
    parser.add_argument("--retries", type=int, help="extra rounds through the nameservers (default: 2)")
    parser.add_argument("--no-ipinfo", dest="ipinfo", action="store_const", const=False, help="skip ipinfo.io")
    parser.add_argument("--token", dest="ipinfo_token", help="ipinfo.io API token (default: $IPINFO_TOKEN)")
    parser.add_argument("--show-resolver", action="store_true", help="print the detected local resolver and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    # Intermixed, so positionals may follow options (dog example.com --json @1.1.1.1)
    # as with dig. Plain parse_args() only allows that from Python 3.12.
    args = parser.parse_intermixed_args(argv)

    if not args.target and not args.show_resolver:
        parser.error("a target is required")
    if args.target and not is_ip(args.target):
        try:
            dns.name.from_text(args.target)
        except dns.exception.DNSException as exc:
            parser.error(f"invalid domain name {args.target!r}: {exc}")

    args.server = None
    args.types = []
    for item in args.extra:
        if item.startswith("@"):
            args.server = item[1:]
            continue
        rdtype = item.upper()
        try:
            dns.rdatatype.from_text(rdtype)
        except dns.rdatatype.UnknownRdatatype:
            parser.error(f"unknown record type: {item}")
        args.types.append(rdtype)
    if args.server and not is_ip(args.server):
        parser.error(f"@server must be an IP address, got {args.server}")
    return args


def resolve_nameservers(cfg: configmod.Config, server: str | None) -> tuple[list[str], str]:
    if server:
        return [server], "command line"
    if cfg.nameservers:
        return cfg.nameservers, "config"
    return detect_nameservers()


@dataclass(kw_only=True)
class Report:
    target: str
    nameservers: list[str]
    nameserver_source: str
    transport: str = "udp"
    edns_payload: int | None
    queries: list[QueryResult]
    ipinfo: dict[str, Info]

    @property
    def ok(self) -> bool:
        return any(q.ok for q in self.queries)

    def to_dict(self) -> dict[str, Any]:
        # Field order is the JSON key order.
        return asdict(self)


def run(args: argparse.Namespace, cfg: configmod.Config) -> Report:
    nameservers, source = resolve_nameservers(cfg, args.server)
    resolver = UdpResolver(cfg, nameservers)

    if is_ip(args.target) and not args.types:
        results = [resolver.reverse(args.target)]
        ips = [args.target]
    else:
        results = [resolver.query(args.target, t) for t in args.types or DEFAULT_TYPES]
        ips = addresses(results)

    info = ipinfo.lookup(ips, cfg.ipinfo_token) if cfg.ipinfo else {}
    return Report(
        target=args.target,
        nameservers=nameservers,
        nameserver_source=source,
        edns_payload=cfg.payload if cfg.edns else None,
        queries=results,
        ipinfo=info,
    )


def render_text(report: Report) -> str:
    edns = f"EDNS0 payload {report.edns_payload}" if report.edns_payload else "no EDNS"
    lines = [
        f"; <<>> dog <<>> {report.target}",
        f";; RESOLVERS: {', '.join(report.nameservers)} (from {report.nameserver_source})",
        f";; TRANSPORT: UDP only, {edns}",
    ]
    for q in report.queries:
        lines.append("")
        header = f";; {q.qname} {q.rdtype}: {q.status}"
        if q.server:
            header += f" from {q.server}"
        if q.size is not None:
            header += f", {q.size} bytes"
        if e := q.edns:
            header += f", server EDNS payload {e.server_payload}" + (", DO" if e.do else "")
        lines.append(header)
        if q.error:
            lines.append(f";; WARNING: {q.error}")
        records = q.records
        if not records:
            continue
        name_w = max(len(r.name) for r in records)
        ttl_w = max(len(str(r.ttl)) for r in records)
        type_w = max(len(r.rdtype) for r in records)
        for r in records:
            lines.append(f"{r.name:<{name_w}}  {r.ttl:>{ttl_w}}  IN  {r.rdtype:<{type_w}}  {r.value}")

    if report.ipinfo:
        lines += ["", ";; IPINFO"]
        ip_w = max(len(ip) for ip in report.ipinfo)
        for ip, info in report.ipinfo.items():
            lines.append(f"{ip:<{ip_w}}  {ipinfo.summarise(info)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # Any flag whose dest matches a Config field overrides it; unset flags are None and ignored.
    overrides = {f.name: getattr(args, f.name) for f in fields(configmod.Config) if hasattr(args, f.name)}
    try:
        cfg = configmod.build(args.config, overrides)
        if args.show_resolver:
            nameservers, source = resolve_nameservers(cfg, args.server)
            print(f"{', '.join(nameservers)} (from {source})")
            return 0
        report = run(args, cfg)
    except (configmod.ConfigError, NoResolverFound) as exc:
        print(f"dog: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report.to_dict(), indent=2) if args.json else render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
