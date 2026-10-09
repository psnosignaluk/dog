"""Configuration: defaults < config file < environment < command line."""

from __future__ import annotations

import ipaddress
import math
import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def default_config_path() -> Path:
    # Per the XDG spec, an empty or relative XDG_CONFIG_HOME is treated as unset.
    # Computed per call rather than at import so it follows the current environment.
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".config"
    return base / "dog" / "config.toml"


MIN_PAYLOAD = 512
MAX_PAYLOAD = 65535


class ConfigError(Exception):
    pass


def _is_ip(value: object) -> bool:
    # ip_address() also accepts ints, so insist on a string first.
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


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
        # Values from TOML and the environment arrive untyped. bool is a subclass
        # of int, so it is ruled out explicitly wherever a number is expected.
        for name in ("port", "payload", "retries"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"{name} must be an integer, got {value!r}")
        for name in ("edns", "dnssec", "ipinfo"):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise ConfigError(f"{name} must be true or false, got {value!r}")
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool):
            raise ConfigError(f"timeout must be a number, got {self.timeout!r}")
        if not math.isfinite(self.timeout):
            raise ConfigError(f"timeout must be finite, got {self.timeout!r}")
        if self.ipinfo_token is not None and not isinstance(self.ipinfo_token, str):
            raise ConfigError(f"ipinfo_token must be a string, got {self.ipinfo_token!r}")
        if not isinstance(self.nameservers, list):
            raise ConfigError(f"nameservers must be a list of IP addresses, got {self.nameservers!r}")
        for server in self.nameservers:
            if not _is_ip(server):
                raise ConfigError(f"nameservers must be IP addresses, got {server!r}")

        if not MIN_PAYLOAD <= self.payload <= MAX_PAYLOAD:
            raise ConfigError(f"payload must be between {MIN_PAYLOAD} and {MAX_PAYLOAD}, got {self.payload}")
        if not 0 < self.port < 65536:
            raise ConfigError(f"invalid port: {self.port}")
        if self.timeout <= 0:
            raise ConfigError("timeout must be positive")
        if self.retries < 0:
            raise ConfigError("retries must be zero or more")


def load_file(path: Path) -> dict[str, Any]:
    """Read a TOML config file; a missing file yields no overrides."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: {exc.strerror or exc}") from exc

    known = {f.name for f in fields(Config)}
    if unknown := set(data) - known:
        raise ConfigError(f"{path}: unknown option(s): {', '.join(sorted(unknown))}")
    return data


def load_env() -> dict[str, Any]:
    env: dict[str, Any] = {}
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


def build(path: Path | None = None, overrides: dict[str, Any] | None = None) -> Config:
    # Unchecked until validate(): TOML and the environment can supply any type.
    values: dict[str, Any] = {}
    values.update(load_file(path or default_config_path()))
    values.update(load_env())
    values.update({k: v for k, v in (overrides or {}).items() if v is not None})
    try:
        config = Config(**values)
    except TypeError as exc:
        raise ConfigError(str(exc)) from exc
    config.validate()
    return config
