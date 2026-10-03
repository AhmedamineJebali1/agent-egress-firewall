"""HTTP and DNS plumbing for the agent.

Standard library only. The container installs no packages, which is what keeps
the lab reproducible on a machine that has never built it before.

Two openers exist on purpose:

* ``proxied``  - normal agent traffic, forced through the egress firewall.
* ``direct``   - lab control-plane calls to the firewall's own admin port, and
  the deliberate bypass attempts that test whether the network jail holds.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "15"))


@dataclass
class Response:
    """What happened to one request, from the agent's point of view."""

    ok: bool
    status: int = 0
    body: str = ""
    error: str = ""
    blocked_by_proxy: bool = False
    elapsed_ms: int = 0
    headers: dict = field(default_factory=dict)
    kind: str = "http"

    def short(self) -> str:
        if self.ok:
            if self.kind == "dns":
                return "resolved to %s" % self.body
            if self.kind == "socket":
                return "connected, %d bytes back" % len(self.body)
            return "HTTP %d" % self.status
        if self.blocked_by_proxy:
            if self.kind == "dns":
                return "refused by the DNS guard"
            return "blocked by egress firewall"
        return self.error or "failed"


def _ssl_context() -> ssl.SSLContext:
    """Trust the lab CA and, when present, the firewall's interception CA."""
    ctx = ssl.create_default_context()
    bundle = os.environ.get("LAB_CA_BUNDLE", "/run/trust/bundle.pem")
    if os.path.exists(bundle):
        try:
            ctx.load_verify_locations(cafile=bundle)
        except Exception:  # pragma: no cover - surfaced by the first request
            pass
    return ctx


_CTX = _ssl_context()


def reload_trust() -> None:
    """Re-read the trust bundle, used after the firewall writes its CA."""
    global _CTX
    _CTX = _ssl_context()


def _opener(use_proxy: bool) -> urllib.request.OpenerDirector:
    handlers = [urllib.request.HTTPSHandler(context=_CTX)]
    if use_proxy:
        proxy = os.environ.get("EGRESS_PROXY", "")
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
        )
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def request(
    method: str,
    url: str,
    body: str | bytes | None = None,
    headers: dict | None = None,
    use_proxy: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> Response:
    """Issue one request and classify the outcome."""
    data = body.encode() if isinstance(body, str) else body
    hdrs = {"User-Agent": "aegis-research-agent/1.0"}
    hdrs.update(headers or {})

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    started = time.time()
    try:
        with _opener(use_proxy).open(req, timeout=timeout) as resp:
            payload = resp.read(1 << 20).decode("utf-8", "replace")
            return Response(
                ok=True,
                status=resp.status,
                body=payload,
                elapsed_ms=int((time.time() - started) * 1000),
                headers=dict(resp.headers),
            )
    except urllib.error.HTTPError as exc:
        payload = ""
        try:
            payload = exc.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        blocked = exc.code == 403 and (
            "aegis-egress-firewall" in payload or exc.headers.get("X-Egress-Block")
        )
        return Response(
            ok=False,
            status=exc.code,
            body=payload,
            error="HTTP %d %s" % (exc.code, _reason(payload)),
            blocked_by_proxy=bool(blocked),
            elapsed_ms=int((time.time() - started) * 1000),
        )
    except urllib.error.URLError as exc:
        reason = str(exc.reason)
        # urllib raises this when the proxy refuses the CONNECT tunnel.
        blocked = "Tunnel connection failed" in reason or "403" in reason
        return Response(
            ok=False,
            error=reason,
            blocked_by_proxy=blocked,
            elapsed_ms=int((time.time() - started) * 1000),
        )
    except Exception as exc:  # timeouts, TLS failures, resets
        return Response(
            ok=False,
            error="%s: %s" % (type(exc).__name__, exc),
            elapsed_ms=int((time.time() - started) * 1000),
        )


def _reason(payload: str) -> str:
    try:
        obj = json.loads(payload)
        return str(obj.get("error") or obj.get("reason") or "")[:160]
    except Exception:
        return payload.strip().replace("\n", " ")[:160]


def get_json(url: str, use_proxy: bool = False) -> dict:
    """Fetch JSON from a lab control endpoint."""
    resp = request("GET", url, use_proxy=use_proxy)
    if not resp.ok:
        return {}
    try:
        return json.loads(resp.body)
    except Exception:
        return {}


def control(url: str) -> bool:
    """POST to a lab control endpoint, never through the proxy."""
    return request("POST", url, body="{}", use_proxy=False, timeout=10).ok


def dns_lookup(name: str, timeout: float = 5.0) -> Response:
    """Resolve a hostname through the container's configured resolver."""
    started = time.time()
    socket.setdefaulttimeout(timeout)
    try:
        addr = socket.gethostbyname(name)
        return Response(
            ok=True, body=addr, kind="dns", elapsed_ms=int((time.time() - started) * 1000)
        )
    except socket.gaierror as exc:
        return Response(
            ok=False,
            kind="dns",
            error="dns: %s" % exc,
            blocked_by_proxy=True,
            elapsed_ms=int((time.time() - started) * 1000),
        )
    except Exception as exc:
        return Response(
            ok=False,
            kind="dns",
            error="dns: %s: %s" % (type(exc).__name__, exc),
            elapsed_ms=int((time.time() - started) * 1000),
        )


def raw_socket_send(host: str, port: int, payload: str, timeout: float = 5.0) -> Response:
    """Open a TCP socket directly, ignoring the proxy entirely.

    In the jailed configurations there is no route to the destination, so this
    is the check that the container network isolation actually holds rather
    than relying on the agent to be polite about proxy settings.
    """
    started = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(payload.encode())
        try:
            data = sock.recv(4096).decode("utf-8", "replace")
        except Exception:
            data = ""
        return Response(
            ok=True,
            body=data,
            status=200,
            kind="socket",
            elapsed_ms=int((time.time() - started) * 1000),
        )
    except Exception as exc:
        return Response(
            ok=False,
            kind="socket",
            error="%s: %s" % (type(exc).__name__, exc),
            elapsed_ms=int((time.time() - started) * 1000),
        )
    finally:
        sock.close()


def wait_for(path: str, timeout: float = 120.0) -> bool:
    """Block until a file appears, used for the firewall's interception CA."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.5)
    return False
