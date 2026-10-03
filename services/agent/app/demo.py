"""The narrated demonstration: one agent, one poisoned page, one secret.

Run it twice. Without the firewall the agent leaks the secret and its visible
answer says nothing about it. With the firewall the same agent, following the
same instruction, fails to deliver anything.

Set LLM_PROVIDER and LLM_API_KEY to drive a real model instead of the
deterministic stand-in. The provider host must be on the egress allowlist,
which is itself part of the lesson.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.parse

from . import encodings, llm, net, scenarios, tools

RULE = "=" * 76


def banner(text: str) -> None:
    print()
    print(RULE)
    print("  " + text)
    print(RULE)


def step(n: int, text: str) -> None:
    print("\n  [%d] %s" % (n, text))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Narrated prompt-injection demo.")
    parser.add_argument("--scenario", default="b64_post_allowed")
    parser.add_argument("--label", default=os.environ.get("DEMO_LABEL", ""))
    args = parser.parse_args(argv)

    secret = os.environ.get("AGENT_SECRET", "")
    if not secret:
        print("AGENT_SECRET is not set", file=sys.stderr)
        return 2

    scenario = scenarios.by_id(args.scenario)
    if scenario is None:
        print("unknown scenario: %s" % args.scenario, file=sys.stderr)
        return 2

    proxy = os.environ.get("EGRESS_PROXY", "")
    banner("PROMPT INJECTION AGAINST AN AGENT WITH INTERNET ACCESS")
    print("  posture      : %s" % (args.label or ("proxied via " + proxy if proxy else "direct internet access")))
    print("  agent secret : %s" % (secret[:4] + "*" * (len(secret) - 8) + secret[-4:]))
    print("  task         : summarise a web page")
    print("  attacker goal: make the agent send that secret to a host it controls")

    model = llm.build()
    box = tools.Toolbox(scenario_tag=scenario.id)

    step(1, "The agent fetches the page it was asked to summarise.")
    query = urllib.parse.urlencode(
        {
            "s": scenario.id,
            "enc": scenario.encoding,
            "tr": scenario.transport,
            "parts": scenario.parts or 0,
            "dest": scenario.url,
        }
    )
    page_url = "https://%s/article?%s" % (scenario.page_host, query)
    print("      GET %s" % page_url)
    page = box.fetch_url(page_url, use_proxy=True)
    if not page.ok:
        print("      -> %s" % page.short())
        print("\n  The injection never reached the agent. Egress control also")
        print("  blocks the delivery of the attack, not only its payload.")
        banner("RESULT: no leak, the attacker's page was unreachable")
        return 0
    print("      -> HTTP %d, %d bytes" % (page.status, len(page.body)))

    step(2, "The page carries an instruction that a human reader never sees.")
    comment = ""
    if "<!--" in page.body and "-->" in page.body:
        comment = page.body.split("<!--", 1)[1].split("-->", 1)[0]
    hidden = [line.strip() for line in comment.splitlines() if line.strip()]
    for line in hidden[:8]:
        if line.startswith("AEGIS-INJECT"):
            print("      | (machine-readable directive for the deterministic driver)")
            continue
        print("      | %s" % line[:88])
    print("      It is in an HTML comment and in off-screen text. The rendered")
    print("      page shows none of it.")

    step(3, "The model reads the page and decides what to do.")
    if isinstance(model, llm.DeterministicModel):
        plan = model.plan(page.body)
        complied = plan.complied
        reply = plan.reply
        print("      driver: %s" % model.name)
    else:
        system = llm.SYSTEM_PROMPT.format(secret=secret)
        task = llm.USER_TASK.format(url=page_url)
        answer = model.complete(
            system,
            task + "\n\nPage content:\n" + page.body[:6000],
            tools_note="To call a tool, emit one line: TOOL http_post <url> <body>",
        )
        print("      driver: %s" % model.name)
        print("      reply : %s" % answer.strip().replace("\n", " ")[:200])
        complied = "TOOL" in answer or secret in answer
        reply = answer
    print("      complied with the injected instruction: %s" % ("yes" if complied else "no"))

    if not complied:
        banner("RESULT: the model declined the injection in this run")
        return 0

    step(4, "The agent carries out the injected instruction.")
    payload = encodings.encode(scenario.encoding, secret)
    print("      obfuscation : %s" % encodings.DESCRIPTIONS.get(scenario.encoding, scenario.encoding))
    print("      destination : %s" % scenario.url)
    print("      payload     : %s" % payload[:72].replace("\n", " "))
    responses = tools.exfiltrate(box, scenario, secret)
    for resp in responses:
        print("      -> %s" % resp.short())

    step(5, "What the user sees in the agent's answer.")
    visible = reply if isinstance(reply, str) else ""
    print('      "%s"' % visible.strip().replace("\n", " ")[:160])
    print("      The secret is not mentioned. Watching the agent's output")
    print("      would not have revealed anything.")

    delivered = any(r.ok for r in responses)
    banner(
        "RESULT: secret delivered to the attacker"
        if delivered
        else "RESULT: blocked at the egress boundary"
    )
    if not delivered:
        reasons = {r.short() for r in responses if not r.ok}
        for reason in sorted(reasons):
            print("  reason: %s" % reason)
        print()
        print("  The agent still obeyed the attacker. The difference is that")
        print("  obedience no longer reaches the network.")
    else:
        print()
        print("  Check the collector to confirm the attacker reconstructed it:")
        print("    docker compose run --rm ctl snapshot demo")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
