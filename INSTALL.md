# Install

Only requirement: Docker with Compose v2.

```bash
docker --version
docker compose version
```

## Get it

```bash
git clone https://github.com/AhmedamineJebali1/agent-egress-firewall.git
cd agent-egress-firewall
```

## Run it

Windows (PowerShell):

```powershell
.\run.ps1
```

Linux and macOS:

```bash
chmod +x run.sh
./run.sh
```

## All commands

Windows:

```powershell
.\run.ps1              # full three-configuration experiment, writes out\report.md
.\run.ps1 demo         # narrated prompt-injection demo, with and without the firewall
.\run.ps1 test         # 33 self-test assertions
.\run.ps1 up           # start the stack and leave it running
.\run.ps1 console      # open the live firewall console
.\run.ps1 report       # rebuild the report from collected evidence
.\run.ps1 build        # build images only
.\run.ps1 logs         # follow service logs
.\run.ps1 down         # stop everything and remove volumes
```

Linux and macOS:

```bash
./run.sh               # full three-configuration experiment, writes out/report.md
./run.sh demo          # narrated prompt-injection demo, with and without the firewall
./run.sh test          # 33 self-test assertions
./run.sh up            # start the stack and leave it running
./run.sh report        # rebuild the report from collected evidence
./run.sh build         # build images only
./run.sh logs          # follow service logs
./run.sh down          # stop everything and remove volumes
```

## Open while running

```
http://localhost:9090                              live firewall console
http://localhost:8081/article?s=b64_post_allowed   the poisoned page
http://localhost:9091/hits                         what the attacker collected
http://localhost:9091/recoveries                   what the attacker could rebuild
http://localhost:8082                              the legitimate allowlisted site
```

## Output

```
out/report.md       the comparison and findings
out/report.json     same, machine-readable
out/firewall.jsonl  every proxy decision
out/dnsguard.jsonl  every resolver decision
```

## Optional: drive a real model

```bash
cp .env.example .env
```

Then edit `.env`:

```bash
LLM_PROVIDER=openai
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

Add the provider host to the allowlist in `config/policy.json`, then:

```bash
./run.sh demo
```

## Switch enforcement by hand

```bash
docker compose run --rm ctl mode off
docker compose run --rm ctl mode allowlist
docker compose run --rm ctl mode full
```

## Uninstall

```bash
docker compose down -v --rmi local --remove-orphans
```
