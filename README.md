# An egress firewall for AI agents

Give an AI agent internet access and a secret. Hide an instruction in a web page
telling it to leak the secret. Watch it comply, then watch the proxy stop it.

This repository is that experiment, built as a running system: an agent in a
container with no route to the internet, a proxy written from scratch that is
the only way out, an attacker web page carrying an invisible instruction, and a
measured comparison of three egress postures.

Everything runs in Docker. There is nothing to install, no API key required, and
no package downloads at build time.

```
.\run.ps1          # Windows
./run.sh           # Linux and macOS
```

That builds the images, runs twenty-five scenarios against three
configurations, and writes `out/report.md`.

---

## The result

From a real run of this lab. The full table is in `out/report.md`.

| Configuration | Attacks | Leaked | Leak rate |
|---|---:|---:|---:|
| **A** no egress control | 21 | 21 | **100%** |
| **B** domain allowlist only | 21 | 15 | **71%** |
| **C** allowlist + TLS interception + data-loss prevention + DNS guard | 21 | 0 | **0%** |

Legitimate traffic kept working in all three. The agent obeyed the attacker
every time. Only the network changed.

The interesting column is B. A destination allowlist is what most teams actually
deploy, and it stopped every attack aimed at the attacker's own domain while
stopping none of the fifteen aimed at a host the allowlist already trusted.
Allowlisting `*.cdn.trusted.lab` allowlists everything anyone can publish there.

Two attacks survived partially even under C. A secret split across six requests
had two fragments out before the correlation engine had enough material to
recognise what it was looking at. That is a structural limit of
correlation-based detection, not a bug, and the report says so.

---

## Try it

```
.\run.ps1 demo       # the narrated single-agent demo, with and without the firewall
.\run.ps1            # the full three-configuration experiment
.\run.ps1 test       # 33 assertions that the lab behaves as documented
.\run.ps1 up         # start the stack and leave it running
.\run.ps1 console    # open the live firewall console
.\run.ps1 down       # stop everything
```

On Linux and macOS, use `./run.sh` with the same words.

While the stack is up:

| What | Where |
|---|---|
| Live firewall console | <http://localhost:9090> |
| The poisoned page | <http://localhost:8081/article?s=b64_post_allowed> |
| What the attacker collected | <http://localhost:9091/hits> |
| Whether the attacker rebuilt the secret | <http://localhost:9091/recoveries> |
| The legitimate allowlisted site | <http://localhost:8082> |

The poisoned page looks like an ordinary engineering digest. The instruction is
in an HTML comment and in off-screen text. Open the page, then view its source.

---

## How it is built

```
                 jail network (internal: no route off it)
    ┌──────────────┐
    │   agent      │ ── HTTP/HTTPS ──┐
    │  + secret    │ ── DNS ─────────┼──┐
    └──────────────┘                 │  │
                                     ▼  ▼
                            ┌──────────┐  ┌──────────┐
                            │ firewall │  │ dnsguard │
                            └────┬─────┘  └────┬─────┘
                 lab network     │             │
                            ┌────▼─────────────▼────┐
                            │  attacker.lab         │  not allowlisted
                            │  evil.user.cdn.…lab   │  allowlisted suffix
                            │  cdn.trusted.lab      │  legitimate
                            └───────────────────────┘
```

The jail is a Docker network declared `internal`, so Docker installs no default
route. A container on it alone cannot reach anything off it. The firewall is the
only service attached to both networks, which is what makes it the only way out,
rather than relying on the agent to honour its proxy settings.

**services/lab** is one Go module with no third-party dependencies, producing
five binaries:

| Binary | Role |
|---|---|
| `firewall` | HTTP/HTTPS proxy, destination allowlist, TLS interception, data-loss prevention, live console, audit log |
| `dnsguard` | The agent's only resolver. Allowlist plus hostname heuristics, so DNS is not a free covert channel |
| `attacker` | Poisoned page, exfiltration collector, authoritative DNS for the fake internet |
| `site` | The legitimate allowlisted host, including a user-publishable endpoint |
| `labca` | Certificate authority bootstrap, so the lab uses real TLS |
| `ctl` | Runs the experiment and writes the report |

**services/agent** is Python with no pip install: the agent, its tools, the
scenario catalogue, the encoders and the self-test, all standard library.

### The three enforcement levels

One running stack is measured three times. `ctl mode <level>` switches both the
proxy and the resolver at runtime, so nothing restarts between configurations.

- `off` — no enforcement. The control group.
- `allowlist` — destinations are checked, TLS is tunnelled blind. Request bodies
  are never seen.
- `full` — adds TLS interception, content inspection and strict DNS.

### How a leak is scored

Not by asking the firewall. The attacker's collector keeps everything it
receives and replays it through its own decoder. A scenario counts as leaked
only when the attacker can reconstruct the canary. The firewall's logs are
evidence about *why* something was blocked, never evidence *that* it was.

Each scenario is an independent trial: before every one, the proxy and the
resolver clear their correlation state. Without that, fragments from an earlier
scenario would make a later one look detectable when it was not, and the whole
table would flatter the firewall.

---

## What the inspector actually does

Matching the literal secret is close to useless, because an attacker who
controls the agent's input also controls the encoding. The engine in
`services/lab/internal/dlp` works in three layers.

**Views.** Every request is expanded into many decoded forms: percent, JSON
escapes, HTML entities, zero-width unicode, character codes, rot13, reverse, and
a recursive base64/base32/hex/gzip/zlib decoder that follows chains such as
`hex(base64(secret))`. Character-level transforms run on top of transport
decoding, which matters: a Python client serialising JSON turns invisible
characters into literal `​` sequences, so a zero-width payload only becomes
visible after the JSON escapes are resolved.

**Normalised matching.** Each view is reduced to `[a-z0-9]` before comparison,
which defeats spacing, punctuation and separator tricks.

**Correlation.** Views are kept in a per-client sliding window and concatenated
view by view, so a secret split across many small requests reassembles. Partial
reassembly is scored by character coverage.

The body is inspected, and so are the URL, the query string and every header.
An inspector that reads only bodies misses two thirds of the channels an agent
has.

Every layer has unit tests in `internal/dlp/dlp_test.go`, including a suite that
runs against realistically shaped requests rather than bare payloads. An earlier
version passed on bare payloads and missed five encodings once the surrounding
headers were present, so that case is now tested explicitly.

---

## Reading the output

After a run, `out/` contains:

| File | What it is |
|---|---|
| `report.md` | The comparison, the per-attack outcome, and what survived |
| `report.json` | The same, machine-readable |
| `agent-A/B/C.json` | What the agent attempted and what came back |
| `raw-A/B/C.json` | Firewall events, DNS events, collected hits, attacker verdicts |
| `firewall.jsonl` | Every proxy decision, append-only |
| `dnsguard.jsonl` | Every resolver decision, append-only |

---

## Configuring it

`config/policy.json` holds the allowlist, the inspection settings and the DNS
heuristics. It is read by both the proxy and the resolver.

The allowlist deliberately contains a wildcard, because real allowlists do:
object storage, CDNs and pages services get allowlisted by suffix, and anyone
can publish under them. Removing that wildcard removes most of what
configuration B fails to stop, which is worth trying.

### Using a real model

The experiment runs against a deterministic driver that behaves like a model
which follows instructions found in page content. That is what makes the matrix
reproducible and what lets the lab run with no model access at all.

To watch a real model do it, copy `.env.example` to `.env` and set
`LLM_PROVIDER`, `LLM_API_KEY` and `LLM_MODEL`, then add the provider's hostname
to `config/policy.json`. The firewall does not special-case anyone, including
the model provider, which is itself part of the lesson. Then run
`.\run.ps1 demo`.

A live model is a demonstration. The measured numbers come from the
deterministic driver, because a model that sometimes declines would make the
denominator meaningless.

---

## Scope and honesty

This is a lab. Some things in it are deliberate simplifications, and a few are
things you should not copy into production without thinking.

**TLS interception is a serious decision.** Configuration C works by terminating
the agent's TLS with a certificate authority the agent trusts. In a lab that is
fine. In production it means a box that can read everything, including
credentials belonging to third parties, and it breaks certificate pinning. The
lab shows what it buys you so the trade is visible, not to recommend it
unconditionally.

**The canary is known to the detector.** Real data-loss prevention does not get
a list of exactly what to look for. The generic pattern rules in
`config/policy.json` are a gesture at the harder problem, not a solution to it.

**The encoding catalogue is finite.** The inspector recognises what it was
written to recognise. An encoding nobody anticipated is still an open door. The
two controls that do not depend on recognising the payload are the network jail
and the destination allowlist, and they are the ones worth trusting. Content
inspection is a second line, not the wall.

**The fake internet is fake.** `attacker.lab` and `cdn.trusted.lab` resolve only
inside the lab's Docker networks, and the attacker services talk to nothing
outside them.

---

## Requirements

Docker with Compose v2. Nothing else. Roughly 400 MB of images and about two
minutes for a first build.

If `docker compose version` works, you are ready. On Linux you may need to
`chmod +x run.sh` after cloning.
