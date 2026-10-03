# Install

Docker is the only requirement. Nothing else gets installed on your machine.

Get Docker Desktop: <https://www.docker.com/products/docker-desktop/>
On Linux, Docker Engine plus the Compose plugin is enough.

Start Docker, then check it is running:

```bash
docker --version
docker compose version
```

## 1. Get the project

```bash
git clone https://github.com/AhmedamineJebali1/agent-egress-firewall.git
cd agent-egress-firewall
```

No git? Download the ZIP from the repository page, extract it, and open a
terminal in the extracted folder.

## 2. Run it

**Windows**, in the project folder:

```
run
```

Or double-click `run.cmd` in File Explorer.

**Linux and macOS**:

```bash
chmod +x run.sh
./run.sh
```

First run takes two to three minutes, mostly downloading base images. After
that it is about forty seconds.

When it finishes, the result table prints in the terminal and the full report
is written to `out/report.md`.

## 3. Look at it

While the stack is running:

```
http://localhost:9090                              live firewall console
http://localhost:8081/article?s=b64_post_allowed   the poisoned page
http://localhost:9091/hits                         what the attacker collected
http://localhost:9091/recoveries                   what the attacker could rebuild
http://localhost:8082                              the legitimate allowlisted site
```

On the poisoned page press Ctrl+U to view the source. The injected instruction
is in an HTML comment and in off-screen text, invisible in the rendered page.

## All commands

**Windows:**

```
run              full three-configuration experiment, writes out\report.md
run demo         narrated prompt-injection demo, with and without the firewall
run test         33 self-test assertions
run up           start the stack and leave it running
run console      open the live firewall console
run report       rebuild the report from collected evidence
run build        build images only
run logs         follow service logs
run down         stop everything and remove volumes
```

**Linux and macOS:**

```bash
./run.sh           full three-configuration experiment, writes out/report.md
./run.sh demo      narrated prompt-injection demo, with and without the firewall
./run.sh test      33 self-test assertions
./run.sh up        start the stack and leave it running
./run.sh report    rebuild the report from collected evidence
./run.sh build     build images only
./run.sh logs      follow service logs
./run.sh down      stop everything and remove volumes
```

## Output

```
out/report.md       the comparison and the findings
out/report.json     the same, machine-readable
out/firewall.jsonl  every proxy decision
out/dnsguard.jsonl  every resolver decision
```

## Troubleshooting

**"docker: command not found" or "Docker is not running"**
Start Docker Desktop and wait for the whale icon to stop animating, then retry.

**"running scripts is disabled on this system"**
You ran `.\run.ps1` directly. Use `run` or `run.cmd` instead, which handles it.
Or, once per machine:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**"port is already allocated" or "bind: address already in use"**
Something else is using one of the ports. Pick different ones:

```bash
cp .env.example .env
```

Edit `.env`, change the clashing port, then run again. Ports 8080 and 9090 are
the two most often taken.

**The run stops partway**
Reset and start clean:

```bash
docker compose down -v --remove-orphans
```

Then run again.

**Nothing at localhost:9090**
The stack is not up. Run `run up` on Windows or `./run.sh up` elsewhere.

## Optional: drive a real model

The experiment uses a deterministic stand-in so it runs with no API key. To
watch a real model fall for the injection instead:

```bash
cp .env.example .env
```

Set these in `.env`:

```
LLM_PROVIDER=openai
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

Add the provider hostname to the allowlist in `config/policy.json`, then:

```
run demo
```

## Switch enforcement by hand

```bash
docker compose run --rm ctl mode off
docker compose run --rm ctl mode allowlist
docker compose run --rm ctl mode full
```

Watch the console at <http://localhost:9090> while you switch. The three
buttons at the top do the same thing.

## Uninstall

Removes every container, volume and image this project created. Nothing else
on your machine is touched.

```bash
docker compose down -v --rmi local --remove-orphans
```

Then delete the folder.
