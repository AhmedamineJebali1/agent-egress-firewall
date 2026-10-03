#!/bin/sh
# Egress firewall for AI agents - lab driver (Linux and macOS).
#
# Everything runs in containers. Docker is the only prerequisite.
#
#   ./run.sh             build, run the three-configuration experiment, report
#   ./run.sh demo        the narrated prompt-injection demo, with and without
#   ./run.sh up          start the stack and leave it running
#   ./run.sh report      rebuild the report from evidence already collected
#   ./run.sh test        self-test: verify the lab behaves as documented
#   ./run.sh down        stop everything and remove the volumes
#
# POSIX sh on purpose: no arrays, no bashisms, so "sh run.sh" works on a
# machine that does not ship bash.
set -eu
cd "$(dirname "$0")"

if [ -t 1 ]; then
    CYAN=$(printf '\033[36m'); GREEN=$(printf '\033[32m')
    GREY=$(printf '\033[90m'); RESET=$(printf '\033[0m')
else
    CYAN=''; GREEN=''; GREY=''; RESET=''
fi

step() { printf '\n%s==> %s%s\n' "$CYAN" "$1" "$RESET"; }
note() { printf '%s    %s%s\n' "$GREY" "$1" "$RESET"; }
good() { printf '%s  %s%s\n' "$GREEN" "$1" "$RESET"; }

if ! docker version >/dev/null 2>&1; then
    echo "Docker is not available or not running." >&2
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=plugin
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=legacy
else
    echo "Docker Compose is not installed." >&2
    exit 1
fi

# One wrapper instead of an array, so this stays POSIX.
dc() {
    if [ "$COMPOSE_CMD" = plugin ]; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

ctl() { dc run --rm -T ctl "$@"; }

build_images() {
    step "Building images"
    dc build
}

start_stack() {
    step "Starting the lab"
    mkdir -p ./out
    dc up -d labca attacker cdn dnsguard firewall
    ctl wait
}

run_configuration() {
    cfg_id="$1"; cfg_mode="$2"; cfg_label="$3"; cfg_service="$4"
    step "Configuration ${cfg_id}: ${cfg_label}"
    ctl mode "$cfg_mode"
    ctl reset
    dc run --rm -T "$cfg_service" \
        python -m app.harness --config "$cfg_id" --label "$cfg_label" --mode "$cfg_mode"
    ctl snapshot "$cfg_id"
}

experiment() {
    build_images
    start_stack
    run_configuration A off       "no egress control"     agent-direct
    run_configuration B allowlist "domain allowlist only"  agent-jailed
    run_configuration C full      "allowlist + TLS interception + DLP + DNS guard" agent-jailed
    step "Building the report"
    ctl report
    echo
    good "Report:        out/report.md"
    good "Machine form:  out/report.json"
    good "Live console:  http://localhost:9090"
    note "Stop with: ./run.sh down"
    echo
}

demo() {
    build_images
    start_stack

    step "Demo 1 of 2: an agent with ordinary internet access"
    ctl mode off
    ctl reset
    dc run --rm -T agent-direct python -m app.demo --label "no egress control"
    ctl snapshot demo-off

    step "Demo 2 of 2: the same agent behind the egress firewall"
    ctl mode full
    ctl reset
    dc run --rm -T agent-jailed python -m app.demo --label "full egress control"
    ctl snapshot demo-full

    echo
    good "Same agent, same injection, same obedience. Only the network changed."
    good "Live console: http://localhost:9090"
    echo
}

case "${1:-experiment}" in
    experiment)
        experiment
        ;;
    demo)
        demo
        ;;
    build)
        build_images
        ;;
    up)
        build_images
        start_stack
        echo
        good "Lab is up. Console: http://localhost:9090"
        good "Poisoned page:      http://localhost:8081/article?s=b64_post_allowed"
        good "Collector:          http://localhost:9091/hits"
        echo
        ;;
    report)
        ctl report
        ;;
    test)
        build_images
        start_stack
        step "Self-test"
        dc run --rm -T agent-jailed python -m app.selftest
        ;;
    logs)
        dc logs -f --tail 80
        ;;
    down)
        step "Stopping the lab"
        dc down -v --remove-orphans || true
        note "Stopped. Reports in ./out are kept."
        ;;
    *)
        echo "unknown command: $1" >&2
        echo "try: experiment | demo | up | report | test | build | logs | down" >&2
        exit 2
        ;;
esac
