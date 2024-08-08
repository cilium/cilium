# no shebang, this script is never run directly
# This script is set up to run before kubelet startup in order to install
# and deploy dnsmasq at first run of a new cluster node without having to
# modify the Kind image. dnsmasq is set up to forward cluster-local DNS
# requests (without suffix) to dockerd, and all other requests to external
# DNS bypassing dockerd. This is required for two reasons:
# (a) in case of BPF Host Routing we bypass iptables thus breaking DNS.
#     See https://github.com/cilium/cilium/issues/23330
# (b) In case host has L7 DNS policy dockerd's iptables rule acts before
#     we redirect the DNS request to proxy port, breaking DNS proxy.

set -euo pipefail

external_dns="1.1.1.1"
for i in /etc/kind-external-dns-*.conf; do
  external_dns="${i#*kind-external-dns-}"
  external_dns="${external_dns%.conf}"
done

if ! dnsmasq -v 2>/dev/null
then
  apt-get update
  apt install -y dnsmasq
  read _ ddns < <(grep nameserver /etc/resolv.conf)
  <<EOF cat >/etc/dnsmasq.conf
no-poll
no-resolv
listen-address=127.0.0.1
server=//$ddns
server=$external_dns
EOF
  conf=$(sed "s/nameserver.*/nameserver 127.0.0.1/" /etc/resolv.conf)
  echo "$conf" > /etc/resolv.conf
  systemctl restart dnsmasq
fi
