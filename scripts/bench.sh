#!/usr/bin/env bash
# Benchmark harness: drives a load generator against Bastion and nginx with matching settings.
#   scripts/bench.sh --target <host|local> --scenario static-small|static-large|tls|h2|h3|proxy|cache
# Writes bench/results/<date>-<scenario>.json. Results taken inside ./dev (Docker) are labelled
# docker-not-comparable: only numbers from the same bare-metal host are comparable.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=local
SCENARIO=static-small
BUILD=${BUILD:-release}
DURATION=${DURATION:-5}
CONNS=${CONNS:-64}
REQS=${REQS:-200000}
BAST_PORT=${BAST_PORT:-18080}
NGX_PORT=${NGX_PORT:-18081}

usage() { echo "usage: $0 --target host|local --scenario static-small|static-large|tls|h2|h3|proxy|cache" >&2; exit 2; }
while [ $# -gt 0 ]; do
    case $1 in
        --target) TARGET=${2:-}; shift 2 ;;
        --scenario) SCENARIO=${2:-}; shift 2 ;;
        *) usage ;;
    esac
done
case $TARGET in host | local) ;; *) usage ;; esac
case $SCENARIO in static-small | static-large | tls | h2 | h3 | proxy | cache) ;; *) usage ;; esac

LABEL=comparable
if [ -f /.dockerenv ] || [ "$TARGET" = local ]; then LABEL=docker-not-comparable; fi

case $SCENARIO in
    static-small) FILE=/small.txt ;;
    static-large) FILE=/large.bin; REQS=2000 ;;
    *) echo "scenario $SCENARIO needs features from a later phase: not implemented yet" >&2; exit 3 ;;
esac

BIN=$ROOT/build/$BUILD/bastion
[ -x "$BIN" ] || { echo "missing $BIN: build it first" >&2; exit 1; }
WORK=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK/www"
head -c 1024 /dev/zero | tr '\0' 'a' > "$WORK/www/small.txt"
head -c 67108864 /dev/zero > "$WORK/www/large.bin"

sed -e "s#@ROOT@#$WORK/www#g" -e "s#@PORT@#$BAST_PORT#g" "$ROOT/bench/bastion.conf" > "$WORK/bastion.conf"
"$BIN" -c "$WORK/bastion.conf" > "$WORK/bastion.log" 2>&1 &
PIDS+=($!)

HAVE_NGINX=0
if command -v nginx > /dev/null; then
    HAVE_NGINX=1
    sed -e "s#@ROOT@#$WORK/www#g" -e "s#@PORT@#$NGX_PORT#g" -e "s#@WORK@#$WORK#g" \
        "$ROOT/bench/nginx.conf" > "$WORK/nginx.conf"
    nginx -c "$WORK/nginx.conf" -p "$WORK" &
    PIDS+=($!)
fi

wait_port() { for _ in $(seq 50); do (exec 3<> "/dev/tcp/127.0.0.1/$1") 2> /dev/null && return 0; sleep 0.1; done; return 1; }
wait_port "$BAST_PORT" || { echo "bastion did not start" >&2; cat "$WORK/bastion.log" >&2; exit 1; }

run_one() { # name port
    local name=$1 port=$2 out
    if command -v wrk > /dev/null && [ "$SCENARIO" = static-small ]; then
        out=$(wrk -t2 -c"$CONNS" -d"${DURATION}s" "http://127.0.0.1:$port$FILE")
        rps=$(printf '%s\n' "$out" | awk '/Requests\/sec/ {print $2}')
        tool=wrk
    elif command -v h2load > /dev/null; then
        out=$(h2load --h1 -n"$REQS" -c"$CONNS" -t2 "http://127.0.0.1:$port$FILE")
        rps=$(printf '%s\n' "$out" | sed -n 's/^finished in .*, \([0-9.]*\) req\/s.*/\1/p')
        tool=h2load
    else
        echo "no load generator (wrk or h2load) found" >&2; exit 1
    fi
    printf '{"server":"%s","tool":"%s","requests_per_sec":%s}' "$name" "$tool" "${rps:-null}"
}

mkdir -p "$ROOT/bench/results"
OUT=$ROOT/bench/results/$(date +%Y-%m-%d)-$SCENARIO.json
{
    printf '{"scenario":"%s","target":"%s","label":"%s","connections":%s,"file":"%s","results":[' \
        "$SCENARIO" "$TARGET" "$LABEL" "$CONNS" "$FILE"
    run_one bastion "$BAST_PORT"
    if [ "$HAVE_NGINX" = 1 ] && wait_port "$NGX_PORT"; then printf ','; run_one nginx "$NGX_PORT"; fi
    printf ']}\n'
} > "$OUT"
cat "$OUT"
echo "wrote $OUT ($LABEL)" >&2
