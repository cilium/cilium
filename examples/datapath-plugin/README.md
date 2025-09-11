## Design

Create a simple transparent proxy example that relies on bpf_sk_assign and
post-Cilium hooks.

Requirements:
* bpf.hostLegacyRouting is enabled
* endpoint routes enabled

1. There will be a single mTLS proxy running on each node.
2. There will be a post-Cilium hook on each LXC egress attachment point (after
   cil_from_container) that steers TCP traffic towards a socket using
   bpf_sk_assign.
3. The proxy server proxies the TCP connection to another proxy instance on
   the target node.


Need to set up policy-based routing to direct traffic coming from the container
to a local socket. It might be better to use mark-based matching.

echo "200 example" >> /etc/iproute2/rt_tables
ip rule add dport 80 lookup example
ip route add example default dev lo
ip route add local default dev lo table example

