#!/bin/sh
# Runs as root on the node through az vmss run-command, which keeps the last 4096 bytes.
ls -l /etc/cni/net.d
crictl pods --name dummy-cni 2>&1 | tail -n 2
crictl ps -a --name install-dummy-cni 2>&1 | tail -n 2
journalctl -u containerd --since "-15 min" --no-pager -o cat | grep -E 'busybox|dummy-cni' | tail -n 4 | cut -c1-250
journalctl -u kubelet --since "-15 min" --no-pager -o cat | grep -E 'busybox|dummy-cni' | tail -n 5 | cut -c1-250
ss -Htnpi '( dport = :443 )' | awk '/"containerd"/ {st=$1; peer=$5; getline; out=""; for (i=1;i<=NF;i++) if ($i ~ /^(bytes_received|lastsnd|lastrcv|retrans|unacked):/) out=out" "$i; print st, peer, out}'
uptime
journalctl --list-boots --no-pager | tail -n 2
