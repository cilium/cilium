#!/bin/sh

ip netns del ns1 2> /dev/null
ip netns del ns2 2> /dev/null

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

ip netns add ns1
ip netns add ns2

ip link add veth1 type veth peer name veth2

ip link set veth1 netns ns1
ip link set veth2 netns ns2

ip netns exec ns1 ip link set dev lo up
ip netns exec ns2 ip link set dev lo up

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up

ip netns exec ns1 ip -6 addr add 2607::1/120 dev veth1
ip netns exec ns2 ip -6 addr add 2607::2/120 dev veth2

ip netns exec ns1 ip link add vxlan1 type vxlan external dev veth1 dstport 0
ip netns exec ns2 ip link add vxlan2 type vxlan external dev veth2 dstport 0

ip netns exec ns1 ip link set dev vxlan1 up
ip netns exec ns2 ip link set dev vxlan2 up

ip netns exec ns1 ip -6 addr add 2607::2:0:1/128 dev vxlan1
ip netns exec ns2 ip -6 addr add 2607::2:0:2/128 dev vxlan2

ip netns exec ns1 ip link add dummy1 type dummy
ip netns exec ns2 ip link add dummy2 type dummy

ip netns exec ns1 ip link set dev dummy1 up
ip netns exec ns2 ip link set dev dummy2 up

ip netns exec ns1 ip -6 addr add 2607::1:0:1/120 dev dummy1
ip netns exec ns2 ip -6 addr add 2607::1:0:2/120 dev dummy2

ip netns exec ns1 ip -6 route add default via 2607::2 dev veth1
ip netns exec ns2 ip -6 route add default via 2607::1 dev veth2

NS1_DU=`ip netns exec ns1 cat /sys/class/net/dummy1/ifindex`
NS1_DP=`ip netns exec ns1 cat /sys/class/net/dummy1/address`
NS1_VX=`ip netns exec ns1 cat /sys/class/net/vxlan1/ifindex`

NS2_DU=`ip netns exec ns2 cat /sys/class/net/dummy2/ifindex`
NS2_DP=`ip netns exec ns2 cat /sys/class/net/dummy2/address`
NS2_VX=`ip netns exec ns2 cat /sys/class/net/vxlan2/ifindex`

ip netns exec ns1 ip -6 neigh add 2607::1:0:2 dev dummy1 lladdr $NS2_DP
ip netns exec ns2 ip -6 neigh add 2607::1:0:1 dev dummy2 lladdr $NS1_DP

cat <<EOF > /tmp/bpf.c
#include "bpf_api.h"
#include <stdint.h>
#include <sys/socket.h>

#define TX_XMIT	0
#define TX_FRWD	1

__section("vxlan1-ingress")
int cls_entry_vx1i(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
//	char fmt[] = "vx1i %u - %x\n";

	skb_get_tunnel_key(skb, &key, sizeof(key), 0);
//	skb->tc_index = 1;
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	return redirect($NS1_DU, TX_FRWD);
}

__section("dummy1-egress")
int cls_entry_vx1e(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
	uint8_t *addr = (uint8_t *)key.remote_ipv6;
//	char fmt[] = "du1e %u - %x\n";

//	if (skb->tc_index)
//		return TC_ACT_OK;

	key.tunnel_id = 42;
	key.tunnel_af = AF_INET6; // -> 2607::2:0:2
	addr[0]  = 0x26;
	addr[1]  = 0x07;
	addr[11] = 2;
	addr[15] = 2;

	skb_set_tunnel_key(skb, &key, sizeof(key), 0);
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	clone_redirect(skb, $NS1_VX, TX_XMIT);
	return TC_ACT_STOLEN;
}

__section("vxlan2-ingress")
int cls_entry_vx2i(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
//	char fmt[] = "vx2i %u - %x\n";

	skb_get_tunnel_key(skb, &key, sizeof(key), 0);
//	skb->tc_index = 1;
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	return redirect($NS2_DU, TX_FRWD);
}

__section("dummy2-egress")
int cls_entry_vx2e(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};
	uint8_t *addr = (uint8_t *)key.remote_ipv6;
//	char fmt[] = "du2e %u - %x\n";

//	if (skb->tc_index)
//		return TC_ACT_OK;

	key.tunnel_id = 42;
	key.tunnel_af = AF_INET6; // -> 2607::2:0:1
	addr[0]  = 0x26;
	addr[1]  = 0x07;
	addr[11] = 2;
	addr[15] = 1;

	skb_set_tunnel_key(skb, &key, sizeof(key), 0);
//	trace_printk(fmt, sizeof(fmt), key.tunnel_id, key.remote_ipv4);

	clone_redirect(skb, $NS2_VX, TX_XMIT);
	return TC_ACT_STOLEN;
}

BPF_LICENSE("GPL");
EOF

clang -O2 -emit-llvm -I./include/ -c /tmp/bpf.c -o - | llc -march=bpf -filetype=obj -o /tmp/bpf.o

# Still need this prio bandaid as we don't have prequeue yet, can become a bottleneck due to locking
ip netns exec ns1 tc qdisc add dev dummy1 root handle eeee: prio bands 3
ip netns exec ns1 tc qdisc add dev vxlan1 ingress

ip netns exec ns2 tc qdisc add dev dummy2 root handle eeee: prio bands 3
ip netns exec ns2 tc qdisc add dev vxlan2 ingress

ip netns exec ns1 tc filter add dev dummy1 parent eeee: bpf da obj /tmp/bpf.o sec dummy1-egress
ip netns exec ns1 tc filter add dev vxlan1 parent ffff: bpf da obj /tmp/bpf.o sec vxlan1-ingress

ip netns exec ns2 tc filter add dev dummy2 parent eeee: bpf da obj /tmp/bpf.o sec dummy2-egress
ip netns exec ns2 tc filter add dev vxlan2 parent ffff: bpf da obj /tmp/bpf.o sec vxlan2-ingress
