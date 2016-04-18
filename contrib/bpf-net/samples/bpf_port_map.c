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

/* compiler workaround */
#define _htonl __builtin_bswap32

/* ip address -> ifindex map */
struct bpf_map_def SEC("maps") container_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__be32), 
        .value_size = sizeof(int),
        .max_entries = 100000,
};

static inline void set_dst_mac(struct __sk_buff *skb, char *mac)
{
        bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 1);
}

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))

static inline void set_ip_tos(struct __sk_buff *skb, __u8 new_tos)
{
        __u8 old_tos = load_byte(skb, TOS_OFF);

        bpf_l3_csum_replace(skb, IP_CSUM_OFF, htons(old_tos), htons(new_tos), 2);
        bpf_skb_store_bytes(skb, TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

#define IS_PSEUDO 0x10
static inline void set_tcp_ip_src(struct __sk_buff *skb, __u32 new_ip)
{
        __u32 old_ip = _htonl(load_word(skb, IP_SRC_OFF));

        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
        bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
}

#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
static inline void set_tcp_dest_port(struct __sk_buff *skb, __u16 new_port)
{
        __u16 old_port = htons(load_half(skb, TCP_DPORT_OFF));

        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
        bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline int do_redirect(struct __sk_buff *skb, int nh_off, int dir)
{
	__u16 dport, off;
	__u8 ip_proto, ip_vl;
        int *ifindex;
        __be32 ip_dest, ip_src;
        char fmt[] = "skb %p len %d ip_dest %x\n";

	ip_proto = load_byte(skb, nh_off +
			     offsetof(struct iphdr, protocol));
	ip_src = load_word(skb, nh_off +
			   offsetof(struct iphdr, saddr));
	ip_dest = load_word(skb, nh_off +
                            offsetof(struct iphdr, daddr));
	if (ip_proto != IPPROTO_TCP)
		return 0;

	ip_vl = load_byte(skb, nh_off);
	if (likely(ip_vl == 0x45))
		nh_off += sizeof(struct iphdr);
	else
		nh_off += (ip_vl & 0xF) << 2;

	bpf_trace_printk(fmt, sizeof(fmt), skb, skb->len, ip_dest);
	dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
	if (dport != 80)
		return 0;

	if (dir == 0) {
        	ifindex = bpf_map_lookup_elem(&container_map, &ip_dest);
 		if (ifindex) {
			set_tcp_dest_port(skb, 8080);
			bpf_clone_redirect(skb, *ifindex, 1);
		}
	} else {
		ifindex = bpf_map_lookup_elem(&container_map, &ip_src);
		if (ifindex)
			set_tcp_dest_port(skb, 80);
	}
	return -1;
}

SEC("ingress")
int handle_ingress(struct __sk_buff *skb)
{
	int ret = 0, nh_off = BPF_LL_OFF + ETH_HLEN;

	if (likely(skb->protocol == __constant_htons(ETH_P_IP)))
		ret = do_redirect(skb, nh_off, 0);

	return ret;
}

SEC("egress")
int handle_egress(struct __sk_buff *skb)
{
	int ret = 0, nh_off = BPF_LL_OFF + ETH_HLEN;

	if (likely(skb->protocol == __constant_htons(ETH_P_IP)))
		ret = do_redirect(skb, nh_off, 1);
	
	return ret;
}
char _license[] SEC("license") = "GPL";
