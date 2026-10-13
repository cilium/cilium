#!/bin/sh
# Runs in the probe container of a node-underlay pod, fed on stdin by probe.sh.
set -u

snapshot() {
  grep -E '^Icmp6(In|Out)Echo' /proc/net/dev_snmp6/eth0
  # Column 12 holds the per-CPU unresolved_discards in hex.
  sum=$(awk 'NR > 1 { printf "0x%s + ", $12 } END { print 0 }' /proc/net/stat/ndisc_cache)
  echo "ndisc_cache.unresolved_discards $((sum))"
  ip neigh show dev eth0 | sed 's/^/neigh /'
}

ping_all() {
  while [ "$#" -ge 2 ]; do
    ts=$(date -u +%FT%TZ)
    rx=$(ping -c 3 -W 2 -w 6 -q "$2" 2>&1 | sed -n 's/.* \([0-9]*\) received,.*/\1/p')
    echo "${ts} $1 $2 ${rx:-0}"
    shift 2
  done
}

mode="$1"
shift
case "${mode}" in
  snapshot) snapshot ;;
  ping) ping_all "$@" ;;
esac
