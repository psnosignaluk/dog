"""Lookups against https://ipinfo.io."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TypeAlias

import httpx

BASE_URL = "https://ipinfo.io"

# A decoded ipinfo.io JSON object, or a local stand-in with an "error" or "bogon" key.
# Values are untrusted, so they stay as object until checked.
Info: TypeAlias = dict[str, object]


async def _lookup(client: httpx.AsyncClient, ip: str) -> Info:
    try:
        response = await client.get(f"/{ip}/json")
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPStatusError as exc:
        return {"ip": ip, "error": f"HTTP {exc.response.status_code}"}
    except httpx.HTTPError as exc:
        return {"ip": ip, "error": str(exc) or type(exc).__name__}
    except ValueError:
        # A 200 that isn't JSON, e.g. a captive portal page. JSONDecodeError and
        # UnicodeDecodeError are both ValueErrors.
        return {"ip": ip, "error": "invalid JSON in response"}
    if not isinstance(data, dict):
        return {"ip": ip, "error": f"expected a JSON object, got {type(data).__name__}"}
    return data


async def _lookup_all(ips: list[str], token: str | None, timeout: float) -> dict[str, Info]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(base_url=BASE_URL, headers=headers, timeout=timeout) as client:
        results = await asyncio.gather(*(_lookup(client, ip) for ip in ips))
    return dict(zip(ips, results))


def is_bogon(ip: str) -> bool:
    """True for addresses that aren't globally routable (private, loopback, link-local, reserved...)."""
    addr = ipaddress.ip_address(ip)
    # ipaddress counts multicast (e.g. 224.0.0.251) as global; ipinfo.io calls it a bogon.
    return not addr.is_global or addr.is_multicast


def lookup(ips: list[str], token: str | None = None, timeout: float = 10.0) -> dict[str, Info]:
    """Look up each IP concurrently; failures are reported per-IP under an "error" key.

    Non-global addresses are never sent to ipinfo.io; they are marked as bogons locally.
    """
    bogons = {ip for ip in ips if is_bogon(ip)}
    public = [ip for ip in ips if ip not in bogons]
    found = asyncio.run(_lookup_all(public, token, timeout)) if public else {}
    return {ip: {"ip": ip, "bogon": True} if ip in bogons else found[ip] for ip in ips}


def _text(info: Info, key: str) -> str | None:
    # The body is untrusted (it may not even come from ipinfo.io), so anything
    # other than a non-empty string is treated as missing.
    value = info.get(key)
    return value if isinstance(value, str) and value else None


def summarise(info: Info) -> str:
    """One-line human summary of an ipinfo response."""
    if "error" in info:
        return f"error: {info['error']}"
    if info.get("bogon") is True:
        return "bogon (private/reserved address)"
    parts = []
    if org := _text(info, "org"):
        parts.append(org)
    location = ", ".join(p for p in (_text(info, "city"), _text(info, "region"), _text(info, "country")) if p)
    if location:
        parts.append(location)
    if hostname := _text(info, "hostname"):
        parts.append(f"host {hostname}")
    return " | ".join(parts) or "no data"
