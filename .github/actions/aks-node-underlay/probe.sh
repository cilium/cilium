#!/usr/bin/env bash
# Pings every node from every other node over each InternalIP and warns per unreachable pair.
set -uo pipefail

ns=kube-system
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "${out}"' EXIT

warn() {
  echo "::warning title=Node underlay::$* ${PHASE}"
}

declare -A ips pods expected
while read -r node addrs; do
  [ -n "${node}" ] && ips[${node}]="${addrs}"
done < <(timeout 60 kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{range .status.addresses[?(@.type=="InternalIP")]}{" "}{.address}{end}{"\n"}{end}')
if [ "${#ips[@]}" -lt 2 ]; then
  warn "found ${#ips[@]} node(s) to probe"
  exit 0
fi
mapfile -t nodes < <(printf '%s\n' "${!ips[@]}" | sort)

while read -r node pod; do
  [ -n "${node}" ] && pods[${node}]="${pod}"
done < <(timeout 60 kubectl -n "${ns}" get pods -l app.kubernetes.io/name=node-underlay \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.spec.nodeName}{" "}{.metadata.name}{"\n"}{end}')
for node in "${nodes[@]}"; do
  [ -n "${pods[${node}]:-}" ] || warn "no node-underlay pod runs on ${node}"
done
[ "${#pods[@]}" -gt 0 ] || exit 0

on_node() {
  local seconds=$1 node=$2
  shift 2
  timeout "${seconds}" kubectl -n "${ns}" exec -i -c probe "${pods[${node}]}" -- \
    sh -s -- "$@" < "${dir}/node.sh"
}

snapshot() {
  local node
  for node in "${!pods[@]}"; do
    on_node 30 "${node}" snapshot > "${out}/${node}.$1" 2>&1 &
  done
  wait
}

snapshot before
for src in "${!pods[@]}"; do
  args=()
  for dst in "${nodes[@]}"; do
    [ "${dst}" = "${src}" ] && continue
    for ip in ${ips[${dst}]}; do
      args+=("${dst}" "${ip}")
    done
  done
  expected[${src}]=$(( ${#args[@]} / 2 ))
  on_node 120 "${src}" ping "${args[@]}" > "${out}/${src}.ping" 2>&1 &
done
wait
snapshot after

echo "Node underlay ${PHASE}, echo replies out of 3 per pair:"
for src in "${nodes[@]}"; do
  [ -n "${pods[${src}]:-}" ] || continue
  got=0
  while read -r ts dst ip rx; do
    got=$(( got + 1 ))
    echo "  ${ts} ${src} -> ${dst} ${ip} ${rx}/3"
    [ "${rx}" = 0 ] && warn "${src} -> ${dst} ${ip} unreachable"
  done < <(grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' "${out}/${src}.ping")
  if [ "${got}" -ne "${expected[${src}]}" ]; then
    warn "probe from ${src} returned ${got} of ${expected[${src}]} pairs"
    sed 's/^/    /' "${out}/${src}.ping"
  fi
done

echo "::group::Node counters ${PHASE}, before -> after"
for node in "${nodes[@]}"; do
  [ -n "${pods[${node}]:-}" ] || continue
  echo "${node}"
  awk 'FILENAME == ARGV[1] { before[$1] = $2; next }
    /^(Icmp6|ndisc_cache)/ { printf "  %-32s %10s -> %10s (%+d)\n", $1, before[$1], $2, $2 - before[$1] }' \
    "${out}/${node}.before" "${out}/${node}.after"
  for when in before after; do
    echo "  neighbors ${when}:"
    sed -n 's/^neigh /    /p' "${out}/${node}.${when}"
  done
done
echo "::endgroup::"
exit 0
