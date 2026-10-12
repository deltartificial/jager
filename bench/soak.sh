#!/bin/sh
# Soak test: run the watcher on the whole system (dry-run, nothing is killed)
# and sample its memory and CPU. Usage: bench/soak.sh [seconds] [interval]
set -e
DUR=${1:-120}; INT=${2:-1s}
BIN=$(dirname "$0")/../target/release/jager
cargo build --release -q
"$BIN" watch --interval "$INT" --dry-run --no-notify --log /dev/null &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
T=0
while [ "$T" -le "$DUR" ]; do
  printf "t=%4ss  " "$T"
  footprint "$PID" 2>/dev/null | awk '/phys_footprint:/{printf "footprint=%s KB  ",$2}'
  ps -o rss=,time= -p "$PID" | awk '{print "rss=" $1 " KB  cpu=" $2}'
  sleep 10; T=$((T + 10))
done
