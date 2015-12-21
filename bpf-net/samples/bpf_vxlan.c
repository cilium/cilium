/* 
 * vxlan tunnel mux and demux based on bcc tunnel_mesh.c
 */
#include <asm/types.h>
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include "bpf_helpers.h"

// TODO
// extend array security group matrix
// map security context to selinux
struct config {
	int tunnel_ifindex;
};

/* encap device id -> encap device ifindex */
struct bpf_map_def SEC("maps") conf = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct config),
	.max_entries = 1,
};

/* <tun_id, remote_ipv4> -> veth ifindex */
struct bpf_map_def SEC("maps") tunkey2if = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct bpf_tunnel_key),
	.value_size = sizeof(int),
	.max_entries = 1024,
};

/* veth ifindex -> <tun_id, remote_ipv4> */
struct bpf_map_def SEC("maps") if2tunkey = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct bpf_tunnel_key),
	.max_entries = 1024,
};

// Handle packets from vxlan device, demux into dest tenant
int handle_ingress(struct __sk_buff *skb)
{
	// TODO export vxlan gbp in ip_tunnel_key ?
	struct bpf_tunnel_key tkey;
	int *ifindex;

	bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0);
        // lookup based on dest ip in inner header
	ifindex = bpf_map_lookup_elem(&tunkey2if, &tkey);
	if (ifindex) {
		//bpf_trace_printk(
		//	"ingress tunnel_id=%d remote_ip=%08x ifindex=%d\n",
		//	tkey.tunnel_id, tkey.remote_ipv4, *ifindex);
		// mark from external
		skb->tc_index = 1;
		bpf_clone_redirect(skb, *ifindex, 1/*ingress*/);
	} else {
		bpf_trace_printk("ingress invalid tunnel_id=%d\n",
				 tkey.tunnel_id);
	}
	return 1;
}

// Handle packets from tenant, mux into vxlan device
int handle_egress(struct __sk_buff *skb)
{
	int ifindex = skb->ifindex;
	struct bpf_tunnel_key *tkey_p, tkey;
	int one = 1;
	struct config *cfg;
		
	cfg = bpf_map_lookup_elem(&conf, &one);
	if (!cfg)
		return 1;

	if (skb->tc_index) {
		//bpf_trace_printk("from external\n");
		// don't send it back out to encap device
		return 1;
	}

	tkey_p = bpf_map_lookup_elem(&if2tunkey, &ifindex);
	if (tkey_p) {
		tkey.tunnel_id = tkey_p->tunnel_id;
		tkey.remote_ipv4 = tkey_p->remote_ipv4;
		bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0);
		bpf_clone_redirect(skb, cfg->tunnel_ifindex, 0/*egress*/);
	}
	return 1;
}
