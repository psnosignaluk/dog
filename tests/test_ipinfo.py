import httpx
import pytest
import respx

from dog import ipinfo


@respx.mock
def test_lookup_sends_token_and_collects_errors():
    ok = respx.get("https://ipinfo.io/1.1.1.1/json").respond(
        json={"ip": "1.1.1.1", "org": "AS64500 Example", "city": "Testville", "country": "GB"}
    )
    respx.get("https://ipinfo.io/8.8.8.8/json").respond(status_code=429)

    result = ipinfo.lookup(["1.1.1.1", "8.8.8.8"], token="secret")

    assert ok.calls[0].request.headers["Authorization"] == "Bearer secret"
    assert ipinfo.summarise(result["1.1.1.1"]) == "AS64500 Example | Testville, GB"
    assert result["8.8.8.8"]["error"] == "HTTP 429"


@respx.mock
def test_lookup_handles_network_errors():
    respx.get("https://ipinfo.io/9.9.9.9/json").mock(side_effect=httpx.ConnectError("boom"))
    assert ipinfo.lookup(["9.9.9.9"])["9.9.9.9"]["error"] == "boom"


@respx.mock
@pytest.mark.parametrize(
    "response, error",
    [
        (httpx.Response(200, html="<html>Sign in to Wi-Fi</html>"), "invalid JSON"),
        (httpx.Response(200, content=b""), "invalid JSON"),
        (httpx.Response(200, content=b"\xff\xfe\x00garbage"), "invalid JSON"),
        (httpx.Response(200, json=["8.8.4.4"]), "expected a JSON object"),
        (httpx.Response(200, json="8.8.4.4"), "expected a JSON object"),
        (httpx.Response(200, content=b"null"), "expected a JSON object"),
    ],
)
def test_lookup_handles_bad_bodies_per_ip(response, error):
    respx.get("https://ipinfo.io/1.1.1.1/json").respond(json={"ip": "1.1.1.1", "org": "AS64500 Example"})
    respx.get("https://ipinfo.io/8.8.4.4/json").mock(return_value=response)

    result = ipinfo.lookup(["1.1.1.1", "8.8.4.4"])

    assert result["1.1.1.1"]["org"] == "AS64500 Example"
    assert result["8.8.4.4"]["ip"] == "8.8.4.4"
    assert error in result["8.8.4.4"]["error"]
    assert ipinfo.summarise(result["8.8.4.4"]).startswith("error: ")


@respx.mock
def test_private_address_is_not_sent():
    route = respx.get("https://ipinfo.io/10.0.0.1/json").respond(json={"ip": "10.0.0.1", "org": "leaked"})

    result = ipinfo.lookup(["10.0.0.1"])

    assert not route.called
    assert not respx.calls
    assert result == {"10.0.0.1": {"ip": "10.0.0.1", "bogon": True}}
    assert "bogon" in ipinfo.summarise(result["10.0.0.1"])


@respx.mock
@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # private
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",  # carrier-grade NAT
        "127.0.0.1",  # loopback
        "169.254.1.1",  # link-local
        "0.0.0.0",  # unspecified
        "192.0.2.1",  # documentation
        "240.0.0.1",  # reserved
        "224.0.0.251",  # multicast
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fe80::1%en0",  # scoped link-local, as seen in resolver output
        "fc00::1",  # unique local
        "2001:db8::1",  # documentation
        "ff02::fb",  # multicast
        "::ffff:10.0.0.1",  # IPv4-mapped private
    ],
)
def test_non_global_addresses_are_local_bogons(ip):
    result = ipinfo.lookup([ip])
    assert not respx.calls
    assert result[ip] == {"ip": ip, "bogon": True}


@respx.mock
def test_mixed_addresses_only_send_global_ones():
    public = respx.get("https://ipinfo.io/1.1.1.1/json").respond(json={"ip": "1.1.1.1", "org": "AS13335 Cloudflare"})

    result = ipinfo.lookup(["192.168.1.1", "1.1.1.1", "::1"])

    assert public.call_count == 1 and len(respx.calls) == 1
    assert list(result) == ["192.168.1.1", "1.1.1.1", "::1"]  # input order kept
    assert result["1.1.1.1"]["org"] == "AS13335 Cloudflare"
    assert result["192.168.1.1"]["bogon"] and result["::1"]["bogon"]


def test_summarise_bogon():
    assert "bogon" in ipinfo.summarise({"ip": "10.0.0.1", "bogon": True})


@pytest.mark.parametrize("bad", [5, 1.5, True, ["x"], {"a": 1}, None, ""])
@pytest.mark.parametrize("key", ["org", "city", "region", "country", "hostname"])
def test_summarise_skips_non_string_fields(key, bad):
    good = {"ip": "1.1.1.1", "org": "AS64500 Example", "city": "Testville", "country": "GB"}
    without = {k: v for k, v in good.items() if k != key}
    # A bad field is treated exactly like a missing one.
    assert ipinfo.summarise({**good, key: bad}) == ipinfo.summarise(without)


def test_summarise_all_fields_bad():
    assert ipinfo.summarise({"org": 1, "city": [], "region": {}, "country": None, "hostname": 2}) == "no data"


@pytest.mark.parametrize("bogon", ["false", 1, "yes"])
def test_summarise_bogon_must_be_true(bogon):
    assert "bogon" not in ipinfo.summarise({"ip": "1.1.1.1", "bogon": bogon, "org": "AS64500 Example"})
