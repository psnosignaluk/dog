"""Lookups against https://ipinfo.io."""

from __future__ import annotations

import asyncio

import httpx

BASE_URL = "https://ipinfo.io"


async def _lookup(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        response = await client.get(f"/{ip}/json")
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        return {"ip": ip, "error": f"HTTP {exc.response.status_code}"}
    except httpx.HTTPError as exc:
        return {"ip": ip, "error": str(exc) or type(exc).__name__}


async def _lookup_all(ips: list[str], token: str | None, timeout: float) -> dict[str, dict]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(base_url=BASE_URL, headers=headers, timeout=timeout) as client:
        results = await asyncio.gather(*(_lookup(client, ip) for ip in ips))
    return dict(zip(ips, results))


def lookup(ips: list[str], token: str | None = None, timeout: float = 10.0) -> dict[str, dict]:
    """Look up each IP concurrently; failures are reported per-IP under an "error" key."""
    if not ips:
        return {}
    return asyncio.run(_lookup_all(ips, token, timeout))


def summarise(info: dict) -> str:
    """One-line human summary of an ipinfo response."""
    if "error" in info:
        return f"error: {info['error']}"
    if info.get("bogon"):
        return "bogon (private/reserved address)"
    parts = []
    if org := info.get("org"):
        parts.append(org)
    location = ", ".join(p for p in (info.get("city"), info.get("region"), info.get("country")) if p)
    if location:
        parts.append(location)
    if hostname := info.get("hostname"):
        parts.append(f"host {hostname}")
    return " | ".join(parts) or "no data"
