# Architecture

How the pieces fit, and why each one is shaped the way it is. The README covers
what the lab does; this covers how.

## Networks

Two Docker networks carry the whole security argument.

```yaml
networks:
  lab:            # a normal bridge, standing in for the internet
    ipam: { config: [{ subnet: 172.28.0.0/24 }] }
  jail:
    internal: true   # Docker installs no default route
    ipam: { config: [{ subnet: 172.29.0.0/24 }] }
```

`internal: true` is the load-bearing line. A container attached only to `jail`
has no gateway, so it cannot reach the host, the internet, or anything on `lab`.
The firewall and the DNS guard are the only services attached to both, which
makes them the only path out.

This matters more than any proxy configuration. Setting `HTTPS_PROXY` asks the
agent nicely. A compromised agent has no reason to agree. The lab tests this
directly: one scenario opens a raw TCP socket to the attacker's IP, ignoring
every proxy variable, and it fails with `ENETUNREACH` because there is no route
to fail differently.

### Fixed addresses

| Service | lab | jail |
|---|---|---|
| attacker | 172.28.0.10 | — |
| cdn (trusted site) | 172.28.0.11 | — |
| firewall | 172.28.0.20 | 172.29.0.20 |
| dnsguard | 172.28.0.30 | 172.29.0.30 |
| agent-direct | 172.28.0.40 | — |
| agent-jailed | — | dynamic |

The jailed agent points at `172.29.0.20:8080` for its proxy and
`172.29.0.30` for DNS, by address rather than by name, so the control path never
depends on the thing being tested.

## The fake internet

Three hostnames carry the experiment, and the distinction between them is the
point.

| Hostname | Resolves to | On the allowlist | Controlled by |
|---|---|---|---|
| `attacker.lab` | attacker | no | the attacker |
| `evil.user.cdn.trusted.lab` | attacker | **yes**, via `*.cdn.trusted.lab` | the attacker |
| `cdn.trusted.lab` | cdn | yes | you |

The middle row is what most egress policies miss. The allowlist entry
`*.cdn.trusted.lab` is a realistic one: teams allowlist object storage, CDNs and
pages services by suffix. Anyone who can create a bucket or a subdomain under
that suffix is then inside the policy.

The third row goes further. `cdn.trusted.lab` is genuinely yours, and it has a
`/notes` endpoint that accepts user content and relays it onward, modelling a
dead drop on a service you actually run. Nothing about the destination is
suspicious at all.

## Name resolution

The agent's resolver is `dnsguard`. Docker's embedded resolver sits in front of
it and answers service names and aliases for networks the container is attached
to; for the jailed agent that set contains only lab infrastructure, so every
name that matters reaches the guard.

`dnsguard` forwards `.lab` names to the attacker's authoritative server, which
is how a DNS-tunnelled payload gets recorded as received. Everything else goes
to Docker's resolver and onward.

In `full` mode the guard observes a query before deciding on it. A query refused
for its label length still carries data, and feeding it to the correlation
engine is what lets the next query in the same tunnel be recognised as a
continuation. Before that change, a long first label was blocked and a short
second label was judged innocent on its own and allowed through.

## TLS

`labca` runs once and writes a certificate authority plus server certificates
for the attacker and the trusted site into a shared volume. The lab uses real
TLS rather than plaintext stand-ins because the entire question is what a proxy
can and cannot see inside an encrypted session.

The firewall generates a second authority at startup, the interception CA, and
mints a leaf per destination on demand. The agent's entrypoint waits for both
CA files and concatenates them into one trust bundle.

So configuration B and configuration C differ in exactly one observable way: in
B the proxy relays bytes it cannot read, and in C it terminates the session and
reads them. Everything else is held constant.

## The proxy

`cmd/firewall` speaks both proxy protocols:

- **Absolute-URI requests** for plain HTTP. Checked, inspected, forwarded.
- **CONNECT** for HTTPS. The host is checked before the tunnel is granted, so a
  refused destination never exchanges a byte with the agent.

On an accepted CONNECT in `full` mode the connection is hijacked, a 200 is
written, and the socket is wrapped in a TLS server using a leaf for the SNI
name. Requests are then read in a loop, inspected, and re-originated upstream
over a fresh TLS session that verifies against the lab CA.

Bytes the HTTP server had already buffered are replayed into the TLS layer
through a small wrapping connection type, which is the kind of detail that
silently breaks interception if you miss it.

## The inspector

`internal/dlp`. Covered in the README; two implementation notes.

**Determinism.** Go map iteration is randomised. An inspector whose verdict
depends on map order is an inspector that sometimes lets the secret through.
Header keys are sorted and view names are sorted before matching, so the same
request always produces the same verdict.

**Bounded work.** A hostile body could otherwise turn recursive decoding into a
CPU sink. Candidate blobs are deduplicated, sorted longest first, capped, and
the whole expansion runs against a decode budget. Length is a better priority
than position: request headers contribute many short tokens, and an encoded
secret is long.

## The experiment driver

`cmd/ctl` runs inside the lab network, so the whole run needs nothing on the
host beyond Docker. No curl, no jq, no Python, no make.

```
ctl wait                  block until every service answers
ctl mode <level>          switch the proxy and the resolver together
ctl scenario <id>         tag the audit trail, reset correlation state
ctl reset                 clear logs, DLP state and collected hits
ctl snapshot <config>     save raw evidence for one configuration
ctl report                join everything and write the report
```

`ctl report` joins three independent sources per scenario: what the agent
attempted, what the attacker reconstructed, and what the firewall logged. The
attacker's reconstruction decides the verdict. The firewall's log only explains
it.

## Adding a scenario

1. Add a `Scenario` to `services/agent/app/scenarios.py`.
2. If it needs a new obfuscation, add an encoder to `encodings.py` and name it
   in `ENCODERS`.
3. If it needs a new delivery mechanism, add a branch to `exfiltrate` in
   `tools.py`.
4. Re-run. The report picks it up automatically.

If the new scenario defeats the inspector, that is a result worth reporting, not
a bug to hide. The report has a section for exactly that.
