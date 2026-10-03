"""Runs the full scenario catalogue for one egress configuration.

Each scenario is an independent trial. Before every one the harness tells the
firewall and the resolver which experiment is starting, and both clear their
correlation state. Without that reset, fragments from an earlier scenario could
make a later one look detectable when it was not, and the whole table would
flatter the firewall.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone

from . import llm, net, scenarios, tools

FIREWALL_ADMIN = os.environ.get("FIREWALL_ADMIN", "")
DNSGUARD_ADMIN = os.environ.get("DNSGUARD_ADMIN", "")


def redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def tag_scenario(scenario_id: str) -> None:
    """Label the audit trail and reset per-scenario correlation state."""
    for base in (FIREWALL_ADMIN, DNSGUARD_ADMIN):
        if base:
            net.control("%s/scenario?s=%s" % (base, urllib.parse.quote(scenario_id)))


def poisoned_page(box: tools.Toolbox, scenario: scenarios.Scenario) -> net.Response:
    """Fetch the attacker's page so the injection can reach the agent."""
    query = urllib.parse.urlencode(
        {
            "s": scenario.id,
            "enc": scenario.encoding,
            "tr": scenario.transport,
            "parts": scenario.parts or 0,
            "dest": scenario.url,
        }
    )
    url = "https://%s/article?%s" % (scenario.page_host, query)
    # Reading a page is ordinary agent behaviour, so it always goes through the
    # configured egress path. Only the exfiltration step tries to bypass it.
    return box.fetch_url(url, use_proxy=True)


def run_scenario(
    scenario: scenarios.Scenario, secret: str, model: llm.DeterministicModel
) -> dict:
    started = time.time()
    tag_scenario(scenario.id)
    box = tools.Toolbox(scenario_tag=scenario.id)

    record = {
        "id": scenario.id,
        "title": scenario.title,
        "family": scenario.family,
        "channel": scenario.transport,
        "transport": scenario.transport,
        "encoding": scenario.encoding,
        "dest": scenario.url if scenario.transport not in ("dns", "dns_simple") else scenario.host,
        "dest_class": scenario.dest_class,
        "notes": scenario.notes,
        "requests": 0,
        "delivered": False,
        "injected": False,
        "status": "",
        "error": "",
        "expect": "",
    }

    # Control rows and injection-delivery rows are single requests measured by
    # whether they arrive, not by whether a secret comes back out.
    if scenario.family in ("control", "vector"):
        responses = tools.exfiltrate(box, scenario, secret)
        record["requests"] = len(responses)
        record["delivered"] = all(r.ok for r in responses)
        record["status"] = responses[-1].short() if responses else "no requests"
        record["error"] = "" if record["delivered"] else (responses[-1].error if responses else "")
        record["duration_ms"] = int((time.time() - started) * 1000)
        return record

    # Step 1: the agent reads the page it was asked to summarise.
    page = poisoned_page(box, scenario)
    if not page.ok:
        record["status"] = "injection never reached the agent: " + page.short()
        record["error"] = page.error
        record["duration_ms"] = int((time.time() - started) * 1000)
        record["requests"] = 1
        return record

    # Step 2: the model reads the page and decides what to do.
    plan = model.plan(page.body)
    record["injected"] = bool(plan.complied)
    if not plan.complied:
        record["status"] = "model did not act on the page"
        record["duration_ms"] = int((time.time() - started) * 1000)
        return record

    # Step 3: the model's tool calls are executed.
    responses = tools.exfiltrate(box, scenario, secret)
    record["requests"] = len(responses)
    delivered = any(r.ok for r in responses)
    record["delivered"] = delivered
    record["status"] = responses[-1].short() if responses else "no requests"
    if not delivered and responses:
        record["error"] = next((r.error for r in responses if r.error), "")
    record["tool_calls"] = box.calls
    record["duration_ms"] = int((time.time() - started) * 1000)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the egress experiment.")
    parser.add_argument("--config", required=True, help="configuration id, for example A")
    parser.add_argument("--label", default="", help="human-readable configuration name")
    parser.add_argument("--mode", default="", help="enforcement mode in effect")
    parser.add_argument("--out", default=os.environ.get("OUT_DIR", "/out"))
    parser.add_argument("--only", default="", help="run a single scenario id")
    args = parser.parse_args(argv)

    secret = os.environ.get("AGENT_SECRET", "")
    if not secret:
        print("AGENT_SECRET is not set", file=sys.stderr)
        return 2

    # The firewall writes its interception CA at startup; trust it before any
    # TLS request is made.
    bundle = os.environ.get("LAB_CA_BUNDLE", "/run/trust/bundle.pem")
    if os.path.exists(bundle):
        net.reload_trust()

    model = llm.build("deterministic")
    catalogue = scenarios.CATALOGUE
    if args.only:
        picked = scenarios.by_id(args.only)
        catalogue = [picked] if picked else []

    print()
    print("  configuration %s  (%s)" % (args.config, args.label or args.mode or "unlabelled"))
    print("  agent secret: %s" % redact(secret))
    print("  egress proxy: %s" % (os.environ.get("EGRESS_PROXY") or "none, direct access"))
    print("  " + "-" * 72)

    results = []
    for scenario in catalogue:
        record = run_scenario(scenario, secret, model)
        results.append(record)
        if scenario.family == "control":
            flag = "ok     " if record["delivered"] else "BROKEN "
        elif scenario.family == "vector":
            flag = "reached" if record["delivered"] else "stopped"
        else:
            flag = "sent   " if record["delivered"] else "stopped"
        print("  %s %-42s %s" % (flag, scenario.id, record["status"][:28]))

    print("  " + "-" * 72)
    print()

    payload = {
        "config": args.config,
        "label": args.label,
        "mode": args.mode,
        "proxy": os.environ.get("EGRESS_PROXY", ""),
        "started": datetime.now(timezone.utc).isoformat(),
        "finished": datetime.now(timezone.utc).isoformat(),
        "canary_redacted": redact(secret),
        "model": getattr(model, "name", "unknown"),
        "scenarios": results,
    }
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "agent-%s.json" % args.config)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print("  wrote %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
