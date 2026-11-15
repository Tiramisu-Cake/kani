#!/usr/bin/env bash
# Log available memory and the largest process once a minute, then run the unchanged perf script.
(
  while sleep 60; do
    avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
    top=$(ps -eo comm=,rss= --sort=-rss | head -1 | awk '{print $1" "int($2/1024)"MB"}')
    echo "PERFPAIR-MEM $(date -u +%H:%M:%S) avail_mb=$avail top=$top"
  done
) &
mon=$!
./scripts/kani-perf.sh
rc=$?
kill $mon 2>/dev/null
exit $rc
