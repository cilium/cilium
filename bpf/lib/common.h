/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/socket.h>

#include "endian.h"
#include "eth.h"
#include "ipv6_core.h"
#include "map_defs.h"
#include "config.h"
#include "socket.h"
#include "tunnel.h"
#include "notify.h"
#include "drop_reasons.h"

#include "source_info.h"

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#if defined(ENABLE_EGRESS_GATEWAY)
#define ENABLE_EGRESS_GATEWAY_COMMON
#endif

#if defined(ENCAP_IFINDEX) || defined(ENABLE_EGRESS_GATEWAY_COMMON) || \
    (defined(ENABLE_DSR) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE)
#define HAVE_ENCAP	1

/* NOT_VTEP_DST is passed to an encapsulation function when the
 * destination of the tunnel is not a VTEP.
 */
#define NOT_VTEP_DST 0
#endif

/* XFER_FLAGS that get transferred from XDP to SKB */
enum {
	XFER_PKT_NO_SVC		= (1 << 0),  /* Skip upper service handling. */
	XFER_UNUSED		= (1 << 1),
	XFER_PKT_SNAT_DONE	= (1 << 2),  /* SNAT is done */
};

/* For use in ctx_get_xfer(), after XDP called ctx_move_xfer(). */
enum {
	XFER_FLAGS = 0,		/* XFER_PKT_* */
};

/* FIB errors from BPF neighbor map. */
#define BPF_FIB_MAP_NO_NEIGH	100

typedef __u64 mac_t;

union v4addr {
	__be32 be32;
	__u8 addr[4];
};

#define THIS_IS_L3_DEV		(ETH_HLEN == 0)

static __always_inline bool validate_ethertype_l2_off(struct __ctx_buff *ctx,
						      int l2_off, __be16 *proto)
{
	const __u64 tot_len = l2_off + ETH_HLEN;
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ethhdr *eth;

	if (THIS_IS_L3_DEV) {
		/* The packet is received on L2-less device. Determine L3
		 * protocol from skb->protocol.
		 */
		*proto = ctx_get_protocol(ctx);
		return true;
	}

	if (data + tot_len > data_end)
		return false;

	eth = data + l2_off;

	*proto = eth->h_proto;

	return eth_is_supported_ethertype(*proto);
}

static __always_inline bool validate_ethertype(struct __ctx_buff *ctx,
					       __be16 *proto)
{
	return validate_ethertype_l2_off(ctx, 0, proto);
}

static __always_inline __maybe_unused bool
__revalidate_data_pull(struct __ctx_buff *ctx, void **data_, void **data_end_,
		       void **l3, const __u32 l3_off, const __u32 l3_len,
		       const bool pull)
{
	const __u64 tot_len = l3_off + l3_len;
	void *data_end;
	void *data;

	/* Verifier workaround, do this unconditionally: invalid size of register spill. */
	if (pull)
		ctx_pull_data(ctx, (__u32)tot_len);
	data_end = ctx_data_end(ctx);
	data = ctx_data(ctx);
	if (data + tot_len > data_end)
		return false;

	/* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
	*data_ = data;
	*data_end_ = data_end;

	*l3 = data + l3_off;
	return true;
}

static __always_inline __u32 get_tunnel_id(__u32 identity)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (identity == WORLD_IPV4_ID || identity == WORLD_IPV6_ID)
		return WORLD_ID;
#endif
	return identity;
}

static __always_inline __u32 get_id_from_tunnel_id(__u32 tunnel_id, __be16 proto  __maybe_unused)
{
#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	if (tunnel_id == WORLD_ID) {
		switch (proto) {
		case bpf_htons(ETH_P_IP):
			return WORLD_IPV4_ID;
		case bpf_htons(ETH_P_IPV6):
			return WORLD_IPV6_ID;
		}
	}
#endif
	return tunnel_id;
}

/* revalidate_data_pull() initializes the provided pointers from the ctx and
 * ensures that the data is pulled in for access. Should be used the first
 * time that the ctx data is accessed, subsequent calls can be made to
 * revalidate_data() which is cheaper.
 * Returns true if 'ctx' is long enough for an IP header of the provided type,
 * false otherwise.
 */
#define revalidate_data_pull(ctx, data, data_end, ip)			\
	__revalidate_data_pull(ctx, data, data_end, (void **)ip, ETH_HLEN, sizeof(**ip), true)

#define revalidate_data_l3_off(ctx, data, data_end, ip, l3_off)		\
	__revalidate_data_pull(ctx, data, data_end, (void **)ip, l3_off, sizeof(**ip), false)

/* revalidate_data() initializes the provided pointers from the ctx.
 * Returns true if 'ctx' is long enough for an IP header of the provided type,
 * false otherwise.
 */
#define revalidate_data(ctx, data, data_end, ip)			\
	revalidate_data_l3_off(ctx, data, data_end, ip, ETH_HLEN)

/* arp is different from the above as we also want to pull in the payload.
 * Returns true if 'ctx' is long enough to be valid ARP packet, false otherwise.
 */
#define revalidate_data_arp_pull(ctx, data, data_end, arp)		\
	__revalidate_data_pull(ctx, data, data_end, (void **)arp,	\
		ETH_HLEN + sizeof(struct arphdr), sizeof(**arp), true)

struct auth_key {
	__u32       local_sec_label;
	__u32       remote_sec_label;
	__u16       remote_node_id; /* zero for local node */
	__u8        auth_type;
	__u8        pad;
};

/* expiration is Unix epoch time in unit nanosecond/2^9 (ns/512). */
struct auth_info {
	__u64       expiration;
};

struct srv6_vrf_key4 {
	struct bpf_lpm_trie_key lpm;
	__u32 src_ip;
	__u32 dst_cidr;
};

struct srv6_vrf_key6 {
	struct bpf_lpm_trie_key lpm;
	union v6addr src_ip;
	union v6addr dst_cidr;
};

struct srv6_policy_key4 {
	struct bpf_lpm_trie_key lpm;
	__u32 vrf_id;
	__u32 dst_cidr;
};

struct srv6_policy_key6 {
	struct bpf_lpm_trie_key lpm;
	__u32 vrf_id;
	union v6addr dst_cidr;
};

#ifndef BPF_F_PSEUDO_HDR
# define BPF_F_PSEUDO_HDR                (1ULL << 4)
#endif

#define IS_ERR(x) (unlikely((x < 0) || (x == CTX_ACT_DROP)))

/* Return value to indicate that proxy redirection is required */
#define POLICY_ACT_PROXY_REDIRECT (1 << 16)

#define NAT_PUNT_TO_STACK	DROP_NAT_NOT_NEEDED

#define NAT_NEEDED		CTX_ACT_OK

/* Cilium metrics reasons for forwarding packets and other stats.
 * If reason is larger than below then this is a drop reason and
 * value corresponds to -(DROP_*), see above.
 *
 * These are shared with pkg/monitor/api/drop.go.
 * When modifying any of the below, those files should also be updated.
 */
#define REASON_FORWARDED		0
#define REASON_PLAINTEXT		3
#define REASON_DECRYPT			4
#define REASON_LB_NO_BACKEND_SLOT	5
#define REASON_LB_NO_BACKEND		6
#define REASON_LB_REVNAT_UPDATE		7
#define REASON_LB_REVNAT_STALE		8
#define REASON_FRAG_PACKET		9
#define REASON_FRAG_PACKET_UPDATE	10
#define REASON_DECRYPTING			12
#define REASON_ENCRYPTING			13
#define REASON_LB_REVNAT_DELETE		14
#define REASON_MTU_ERROR_MSG			15

/* Cilium metrics direction for dropping/forwarding packet */
enum metric_dir {
	METRIC_INGRESS = 1,
	METRIC_EGRESS,
	METRIC_SERVICE
} __packed;

/* Magic ctx->mark identifies packets origination and encryption status.
 *
 * The upper 16 bits plus lower 8 bits (e.g. mask 0XFFFF00FF) contain the
 * packets security identity. The lower/upper halves are swapped to recover
 * the identity.
 *
 * In case of MARK_MAGIC_PROXY_EGRESS_EPID the upper 16 bits carry the Endpoint
 * ID instead of the security identity and the lower 8 bits will be zeroes.
 *
 * The 4 bits at 0X0F00 provide
 *  - the magic marker values which indicate whether the packet is coming from
 *    an ingress or egress proxy, a local process and its current encryption
 *    status.
 *
 * The 4 bits at 0xF000 provide
 *  - the key index to use for encryption when multiple keys are in-flight.
 *    In the IPsec case this becomes the SPI on the wire.
 */
/*						Packet mark content: */
#define MARK_MAGIC_HOST_MASK		0x0F00
#define MARK_MAGIC_SKIP_TPROXY		0x0800
#define MARK_MAGIC_PROXY_EGRESS_EPID	0x0900 /* source endpoint ID */
#define MARK_MAGIC_PROXY_INGRESS	0x0A00 /* source identity (upstream traffic only) */
#define MARK_MAGIC_PROXY_EGRESS		0x0B00 /* source identity (upstream traffic only) */
#define MARK_MAGIC_HOST			0x0C00
#define MARK_MAGIC_DECRYPT		0x0D00 /* IPSec: source node ID (ingress encrypted traffic)
						* WireGuard: source identity (ingress decrypted traffic)
						*/
#define MARK_MAGIC_ENCRYPT		0x0E00
#define MARK_MAGIC_IDENTITY		0x0F00 /* source identity */
#define MARK_MAGIC_TO_PROXY		0x0200
#define MARK_MAGIC_SNAT_DONE		0x0300
#define MARK_MAGIC_OVERLAY		0x0400 /* source identity */
#define MARK_MAGIC_EGW_DONE		0x0500 /* source identity */

#define MARK_MAGIC_KEY_MASK		0xFF00

/* Note, MARK_MAGIC_HEALTH is user-facing UAPI for LB! The tcx datapath will
 * not see the MARK_MAGIC_HEALTH value given sock_lb is going to reset it.
 */
#define MARK_MAGIC_HEALTH		0x0D00

/* MARK_MAGIC_CLUSTER_ID shouldn't interfere with MARK_MAGIC_TO_PROXY. Lower
 * 8bits carries cluster_id, and when extended via the 'max-connected-clusters'
 * option, the upper 16bits may also be used for cluster_id, starting at the
 * most significant bit.
 */
#define MARK_MAGIC_CLUSTER_ID		MARK_MAGIC_TO_PROXY

/*
 * ctx->tc_index uses
 *
 * cilium_host @egress
 *   bpf_host -> bpf_lxc
 */
#define TC_INDEX_F_FROM_INGRESS_PROXY	1
#define TC_INDEX_F_FROM_EGRESS_PROXY	2
#define TC_INDEX_F_SKIP_NODEPORT	4
#define TC_INDEX_F_SKIP_HEALTH_CHECK	8
#define TC_INDEX_F_SKIP_HOST_FIREWALL	16

#define CB_NAT_FLAGS_REVDNAT_ONLY	(1 << 0)

/*
 * For use in ctx_{load,store}_meta(), which operates on sk_buff->cb or
 * the cilium_xdp_scratch pad.
 * The verifier only exposes the first 5 slots in cb[], so this enum
 * only contains 5 entries. Aliases are added to the slots to re-use
 * them under different names in different parts of the datapath.
 * Take care to not clobber slots used by other functions in the same
 * code path.
 */
/* ctx_{load,store}_meta() usage: */
enum {
	CB_SRC_LABEL,
#define	CB_PORT			CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_HINT			CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_PROXY_MAGIC		CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_ENCRYPT_MAGIC	CB_SRC_LABEL	/* Alias, non-overlapping */
#define	CB_DST_ENDPOINT_ID	CB_SRC_LABEL    /* Alias, non-overlapping */
#define CB_SRV6_SID_1		CB_SRC_LABEL	/* Alias, non-overlapping */
#define CB_VERDICT		CB_SRC_LABEL	/* Alias, non-overlapping */
	CB_1,
#define	CB_DELIVERY_REDIRECT	CB_1		/* Alias, non-overlapping */
#define	CB_NAT_46X64		CB_1		/* Alias, non-overlapping */
#define	CB_ADDR_V4		CB_1		/* Alias, non-overlapping */
#define	CB_ADDR_V6_1		CB_1		/* Alias, non-overlapping */
#define	CB_IPCACHE_SRC_LABEL	CB_1		/* Alias, non-overlapping */
#define	CB_SRV6_SID_2		CB_1		/* Alias, non-overlapping */
#define	CB_CLUSTER_ID_EGRESS	CB_1		/* Alias, non-overlapping */
#define	CB_TRACED		CB_1		/* Alias, non-overlapping */
	CB_2,
#define	CB_ADDR_V6_2		CB_2		/* Alias, non-overlapping */
#define CB_SRV6_SID_3		CB_2		/* Alias, non-overlapping */
#define	CB_CLUSTER_ID_INGRESS	CB_2		/* Alias, non-overlapping */
#define CB_NAT_FLAGS		CB_2		/* Alias, non-overlapping */
	CB_3,
#define	CB_ADDR_V6_3		CB_3		/* Alias, non-overlapping */
#define	CB_FROM_HOST		CB_3		/* Alias, non-overlapping */
#define CB_SRV6_SID_4		CB_3		/* Alias, non-overlapping */
#define CB_DSR_L3_OFF		CB_3		/* Alias, non-overlapping */
	CB_CT_STATE,
#define	CB_ADDR_V6_4		CB_CT_STATE	/* Alias, non-overlapping */
#define	CB_ENCRYPT_IDENTITY	CB_CT_STATE	/* Alias, non-overlapping,
						 * Not used by xfrm.
						 */
#define	CB_SRV6_VRF_ID		CB_CT_STATE	/* Alias, non-overlapping */
#define	CB_FROM_TUNNEL		CB_CT_STATE	/* Alias, non-overlapping */
};

/* Magic values for CB_FROM_HOST.
 * CB_FROM_HOST overlaps with CB_NAT46_STATE, so this value must be distinct
 * from any in enum NAT46 below!
 */
#define FROM_HOST_L7_LB 0xFACADE42

#define TUPLE_F_OUT		0	/* Outgoing flow */
#define TUPLE_F_IN		1	/* Incoming flow */
#define TUPLE_F_RELATED		2	/* Flow represents related packets */
#define TUPLE_F_SERVICE		4	/* Flow represents packets to service */

enum ct_dir {
	CT_EGRESS,
	CT_INGRESS,
	CT_SERVICE,
} __packed;

enum ct_status {
	CT_NEW,
	CT_ESTABLISHED,
	CT_REPLY,
	CT_RELATED,
} __packed;

struct ipv6_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	union v6addr	daddr;
	union v6addr	saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

struct lb6_reverse_nat {
	union v6addr address;
	__be16 port;
} __packed;

struct lb4_reverse_nat {
	__be32 address;
	__be16 port;
} __packed;

static __always_inline __u64 ctx_adjust_hroom_flags(void)
{
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
}

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct lpm_v6_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[16];
};

struct lpm_val {
	/* Just dummy for now. */
	__u8 flags;
};

/* Older kernels don't support the larger tunnel key structure and we don't
 * need it since we only want to retrieve the tunnel ID anyway.
 */
#define TUNNEL_KEY_WITHOUT_SRC_IP offsetof(struct bpf_tunnel_key, local_ipv4)

#include "overloadable.h"
