"""Configuration: defaults < config file < environment < command line."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

DEFAULT_CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "dog" / "config.toml"

MIN_PAYLOAD = 512
MAX_PAYLOAD = 65535


class ConfigError(Exception):
    pass


@dataclass
class Config:
    # Empty means "use the system's local resolver".
    nameservers: list[str] = field(default_factory=list)
    port: int = 53
    # Advertised EDNS(0) UDP payload size. Larger lets bigger answers fit in one
    # UDP datagram, which matters because we never fall back to TCP.
    payload: int = 4096
    edns: bool = True
    dnssec: bool = False
    timeout: float = 3.0
    retries: int = 2
    ipinfo: bool = True
    ipinfo_token: str | None = None

    def validate(self) -> None:
        if not MIN_PAYLOAD <= self.payload <= MAX_PAYLOAD:
            raise ConfigError(f"payload must be between {MIN_PAYLOAD} and {MAX_PAYLOAD}, got {self.payload}")
        if not 0 < self.port < 65536:
            raise ConfigError(f"invalid port: {self.port}")
        if self.timeout <= 0:
            raise ConfigError("timeout must be positive")
        if self.retries < 0:
            raise ConfigError("retries must be zero or more")


def load_file(path: Path) -> dict:
    """Read a TOML config file; a missing file yields no overrides."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    known = {f.name for f in fields(Config)}
    if unknown := set(data) - known:
        raise ConfigError(f"{path}: unknown option(s): {', '.join(sorted(unknown))}")
    return data


def load_env() -> dict:
    env = {}
    if token := os.environ.get("IPINFO_TOKEN"):
        env["ipinfo_token"] = token
    if servers := os.environ.get("DOG_NAMESERVERS"):
        env["nameservers"] = [s.strip() for s in servers.split(",") if s.strip()]
    if payload := os.environ.get("DOG_PAYLOAD"):
        try:
            env["payload"] = int(payload)
        except ValueError as exc:
            raise ConfigError(f"DOG_PAYLOAD must be an integer, got {payload!r}") from exc
    return env


def build(path: Path | None = None, overrides: dict | None = None) -> Config:
    values: dict = {}
    values.update(load_file(path or DEFAULT_CONFIG_PATH))
    values.update(load_env())
    values.update({k: v for k, v in (overrides or {}).items() if v is not None})
    try:
        config = Config(**values)
    except TypeError as exc:
        raise ConfigError(str(exc)) from exc
    config.validate()
    return config
