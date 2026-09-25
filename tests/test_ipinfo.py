import httpx
import respx

from dog import ipinfo


@respx.mock
def test_lookup_sends_token_and_collects_errors():
    ok = respx.get("https://ipinfo.io/192.0.2.1/json").respond(
        json={"ip": "192.0.2.1", "org": "AS64500 Example", "city": "Testville", "country": "GB"}
    )
    respx.get("https://ipinfo.io/192.0.2.2/json").respond(status_code=429)

    result = ipinfo.lookup(["192.0.2.1", "192.0.2.2"], token="secret")

    assert ok.calls[0].request.headers["Authorization"] == "Bearer secret"
    assert ipinfo.summarise(result["192.0.2.1"]) == "AS64500 Example | Testville, GB"
    assert result["192.0.2.2"]["error"] == "HTTP 429"


@respx.mock
def test_lookup_handles_network_errors():
    respx.get("https://ipinfo.io/192.0.2.3/json").mock(side_effect=httpx.ConnectError("boom"))
    assert ipinfo.lookup(["192.0.2.3"])["192.0.2.3"]["error"] == "boom"


def test_summarise_bogon():
    assert "bogon" in ipinfo.summarise({"ip": "10.0.0.1", "bogon": True})
