# dog

`dig` + [ipinfo.io](https://ipinfo.io) in one command.

DNS goes **over UDP only**, with EDNS(0) turned on to get a larger response buffer. dog never falls back to TCP or uses DNS-over-HTTPS. If an answer doesn't fit in one datagram, dog tells you it was truncated.

```sh
uv run dog example.com                 # A + AAAA, then ipinfo for each address
uv run dog example.com MX TXT @1.1.1.1 # dig-style types and @server
uv run dog 8.8.8.8                     # PTR lookup + ipinfo
uv run dog org DNSKEY --dnssec --payload 1232
uv run dog --show-resolver             # which local resolver will be used
uv run dog example.com --json
```

## Resolver detection

Nameservers are chosen in this order: `@server` on the command line, `nameservers` in the config file or `$DOG_NAMESERVERS`, then the system resolver. The system resolver is read from `/etc/resolv.conf`, or from `scutil --dns` on macOS if that file is empty.

## Configuration

Settings are layered: defaults, then `~/.config/dog/config.toml` (or `--config PATH`), then environment variables, then command-line flags. Each layer overrides the one before it.

```toml
nameservers = []      # empty = use the detected local resolver
port = 53
payload = 4096        # EDNS UDP payload size to advertise (512–65535)
edns = true
dnssec = false        # set the DO bit
timeout = 3.0         # seconds per attempt
retries = 2           # extra rounds through the nameserver list
ipinfo = true
ipinfo_token = ""     # or $IPINFO_TOKEN; optional, raises rate limits
```

Environment variables: `IPINFO_TOKEN`, `DOG_NAMESERVERS` (comma-separated), `DOG_PAYLOAD`.

A note on payload size: the resolver also limits how much it will send over UDP. A bigger advertised buffer only helps up to that limit. Very large buffers also mean IP fragmentation, which some networks drop. 1232 is the widely recommended safe value, and 4096 is the default here.

## Development

Supports Python 3.10 and later. Development uses the version pinned in `.python-version`.

```sh
uv run pytest
# check every supported version:
for v in 3.10 3.11 3.12 3.13 3.14; do uv run --isolated --python $v pytest -q; done
```
