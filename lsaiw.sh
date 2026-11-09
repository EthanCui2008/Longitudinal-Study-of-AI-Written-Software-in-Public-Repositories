#!/usr/bin/env bash
# LSAIW runner for Docker on WSL (Docker Desktop) or any Linux host with docker compose.
#
#   ./lsaiw.sh test [--resume]      test run in the foreground; Ctrl+C stops it gracefully
#                                   (starts fresh: the previous results_test/ is moved to results_test.prev/)
#   ./lsaiw.sh full                 full run in the background; re-run to resume after a stop
#   ./lsaiw.sh logs [test]          follow the log
#   ./lsaiw.sh status               containers, health and dashboard URLs
#   ./lsaiw.sh stop [test]          graceful stop (finishes in-flight batches, up to 5 min)
#   ./lsaiw.sh analyze [--test] [--detrend]
#   ./lsaiw.sh export [--test]
#   ./lsaiw.sh dashboard [--test]   view an existing DB without running the pipeline
#   ./lsaiw.sh tailscale up|down|url
#   ./lsaiw.sh build                rebuild the image (also done automatically by test/full)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# Run as your WSL user so results/ stays editable without sudo
export LSAIW_UID="$(id -u)" LSAIW_GID="$(id -g)"
PORT_FULL="${LSAIW_PORT_FULL:-8765}" PORT_TEST="${LSAIW_PORT_TEST:-8766}"

die() { echo "error: $*" >&2; exit 1; }
dc() { docker compose "$@"; }

preflight() {
    command -v docker >/dev/null || die "docker not found. Install Docker Desktop and enable WSL integration for this distro"
    docker info >/dev/null 2>&1 || die "Docker isn't running (start Docker Desktop)"
    [[ -f keys.env ]] || die "keys.env missing: cp keys.env.example keys.env, then add your GitHub token"
    case "$PWD" in
        /mnt/?/*) echo "warning: this checkout is on a Windows drive ($PWD). Bind mounts there are slow and" \
                       "SQLite locking is unreliable; clone into the WSL filesystem (e.g. ~/lsaiw) instead." >&2 ;;
    esac
    mkdir -p results results_test   # created by you, not by docker as root
    for d in results results_test; do
        [[ -z "$(find "$d" ! -user "$LSAIW_UID" -print -quit 2>/dev/null)" ]] ||
            die "$d/ has files owned by another user (an earlier container ran as root). Fix: sudo chown -R \"\$USER:\" $d"
    done
}

urls() {
    local port=$1
    echo "  this PC:   http://localhost:$port"
    local ts
    ts="$(ts_name)" && [[ -n "$ts" ]] && {
        [[ $port == "$PORT_TEST" ]] && echo "  tailnet:   http://$ts:8080" || echo "  tailnet:   http://$ts"
    }
    return 0
}

ts_name() {
    dc --profile tailscale ps --status running -q tailscale 2>/dev/null | grep -q . || return 1
    dc --profile tailscale exec -T tailscale tailscale status --json 2>/dev/null \
        | grep -m1 '"DNSName"' | sed -E 's/.*"DNSName": *"([^"]*)\.?".*/\1/; s/\.$//'
}

test_flag() { [[ "${1:-}" == test || "${1:-}" == --test ]] && echo test || echo full; }

cmd="${1:-help}"; shift || true
case "$cmd" in
    test)
        preflight
        if [[ "${1:-}" != --resume ]] && [[ -n "$(ls -A results_test 2>/dev/null)" ]]; then
            rm -rf results_test.prev && mv results_test results_test.prev && mkdir results_test
            echo "previous test results moved to results_test.prev/"
        fi
        echo "dashboard:"; urls "$PORT_TEST"
        dc --profile test up --build test
        echo; echo "next: ./lsaiw.sh analyze --test"
        ;;
    full)
        preflight
        dc up -d --build full
        echo "full run started (resumes from results/pipeline.db if present). dashboard:"; urls "$PORT_FULL"
        echo "logs: ./lsaiw.sh logs    stop: ./lsaiw.sh stop"
        ;;
    logs)  svc="$(test_flag "${1:-}")"; dc --profile test logs -f --tail 50 "$svc" ;;
    stop)  svc="$(test_flag "${1:-}")"; dc --profile test stop "$svc" ;;
    status)
        dc --profile test --profile tailscale ps -a
        echo; echo "full run:"; urls "$PORT_FULL"; echo "test run:"; urls "$PORT_TEST"
        ;;
    analyze|export|dashboard)
        preflight
        svc=full; args=()
        for a in "$@"; do [[ $a == --test ]] && svc=test; args+=("$a"); done
        ports=(); [[ $cmd == dashboard ]] && ports=(--service-ports)
        dc --profile test run --rm "${ports[@]}" "$svc" "$cmd" "${args[@]}"
        ;;
    tailscale)
        case "${1:-up}" in
            up)
                [[ -f tailscale.env ]] || die "tailscale.env missing: cp tailscale.env.example tailscale.env, then add an auth key"
                dc --profile tailscale up -d tailscale
                echo "waiting for the tailnet name..."
                for _ in $(seq 20); do n="$(ts_name || true)"; [[ -n "$n" ]] && break; sleep 2; done
                [[ -n "${n:-}" ]] && echo "full run: http://$n    test run: http://$n:8080" \
                                 || echo "not up yet; check ./lsaiw.sh tailscale url in a moment"
                ;;
            down) dc --profile tailscale stop tailscale ;;
            url)  n="$(ts_name)" || die "tailscale sidecar not running"; echo "full: http://$n    test: http://$n:8080" ;;
            *)    die "usage: ./lsaiw.sh tailscale up|down|url" ;;
        esac
        ;;
    build) dc build ;;
    help|-h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown command '$cmd' (./lsaiw.sh help)" ;;
esac
