/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_MCAST_H_
#define __LIB_MCAST_H_

#include <bpf/api.h>
#include <linux/ip.h>
#include <linux/igmp.h>

#include "bpf/ctx/skb.h"
#include "bpf/helpers.h"
#include "bpf/helpers_skb.h"
#include "lib/common.h"
#include "lib/drop.h"
#include "lib/eth.h"
#include "linux/bpf.h"

/* the below structures are define outside of an IFDEF guard to satisfy
 * enterprise_bpf_alignchecker.c requirement
 */

/* mcast_subscriber flags */
enum {
	/* indicates subscriber is remote and ifindex is the exit interface */
	MCAST_SUB_F_REMOTE = (1U << 0)
};

/* 32bit big endian multicast group address for use with ipv4 protocol */
typedef __be32 mcast_group_v4;

/* structure to describe a local or remote subscriber of a multicast group
 * for the ipv4 protocol.
 */
struct mcast_subscriber_v4 {
	/* source address of the subscriber, big endian */
	__be32 saddr;
	/* local ifindex of subscriber of exit interface is remote subscriber */
	__u32 ifindex;
	/* reserved */
	__u16 pad1;
	/* reserved */
	__u8  pad2;
	/* flags for further subscriber description */
	__u8  flags;
};

#ifdef ENABLE_MULTICAST

#define MCAST_MAX_GROUP 1024
#define MCAST_MAX_SUBSCRIBERS 1024
/* used to bound iteration of group records within an igmpv3 membership report */
#define MCAST_MAX_GREC 24

/* Multicast group map is a nested hash of maps.
 * The outer map is keyed by a 'mcast_group_v4' multicast group address.
 * The inner value is an hash map of 'mcast_subscriber_v4' structures keyed
 * by a their IPv4 source address in big endian format.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, mcast_group_v4);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MCAST_MAX_GROUP);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Multicast group subscribers inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(key_size, sizeof(__be32));
		__uint(value_size, sizeof(struct mcast_subscriber_v4));
		__uint(max_entries, MCAST_MAX_SUBSCRIBERS);
		__uint(map_flags, CONDITIONAL_PREALLOC);
	});
} cilium_mcast_group_outer_v4_map __section_maps_btf;

/* lookup a subscriber map for the given ipv4 multicast group
 * returns a void pointer to a inner subscriper map if one exists
 */
static __always_inline void *mcast_lookup_subscriber_map(__be32 *group)
{
	return map_lookup_elem(&cilium_mcast_group_outer_v4_map, group);
}

/* returns 1 if ip4 header is followed by an IGMP payload, 0 if not */
static __always_inline bool mcast_ipv4_is_igmp(const struct iphdr *ip4)
{
	if (ip4->protocol == IPPROTO_IGMP)
		return 1;
	return 0;
}

/* returns the IGMP type for a given IGMP message
 * a call to 'mcast_ipv4_is_igmp' must be used prior to this call to ensure an
 * igmp message follows the ipv4 header
 */
static __always_inline __s32 mcast_ipv4_igmp_type(const struct iphdr *ip4,
						  const void *data,
						  const void *data_end)
{
	const struct igmphdr *hdr;
	int ip_len = ip4->ihl * 4;

	if (data + ETH_HLEN + ip_len + sizeof(struct igmphdr) > data_end)
		return DROP_INVALID;

	hdr = data + ETH_HLEN + ip_len;
	return hdr->type;
}

/* add a subscriber to a subscriber map */
/* returns 1 on success or DROP_INVALID for error */
static __always_inline __s32 mcast_ipv4_add_subscriber(void *map,
						       struct mcast_subscriber_v4 *sub)
{
	if ((map_update_elem(map, &sub->saddr, sub, BPF_ANY) != 0))
		return DROP_INVALID;
	return 1;
}

/* remove a subscriber to a subscriber map */
/* always returns 1 */
static __always_inline void mcast_ipv4_remove_subscriber(void *map,
							 struct mcast_subscriber_v4 *sub)
{
	map_delete_elem(map, &sub->saddr);
}

static __always_inline __s32 mcast_ipv4_handle_v3_membership_report(void *ctx,
								    void *group_map,
								    const struct iphdr *ip4,
								    const void *data,
								    const void *data_end)
{
	struct mcast_subscriber_v4 subscriber = {
		.saddr = ip4->saddr,
		.ifindex = ctx_get_ingress_ifindex(ctx)
	};
	const struct igmpv3_report *rep;
	const struct igmpv3_grec *rec;
	int ip_len = ip4->ihl * 4;
	__s32 subscribed = 0;
	void *sub_map = 0;
	__u16 ngrec = 0;
	__u32 i = 0;

	if (data + ETH_HLEN + ip_len + sizeof(struct igmpv3_report) > data_end)
		return DROP_INVALID;

	rep = data + ETH_HLEN + ip_len;

	ngrec = bpf_ntohs(rep->ngrec);

	if (ngrec > MCAST_MAX_GREC)
		return DROP_INVALID;

	/* start a bounded loop which exits when we hit the total number of
	 * group records in the membership report.
	 *
	 * add our subscriber into each group advertised in the report.
	 */
#pragma unroll
	for (i = 0; i < MCAST_MAX_GREC; i++) {
		/* Wrap this in an if, instead of breaking out of the loop,
		 * so unroll has a constant number of iterations.
		 *
		 * Compiler was not happy with a continue; statement and the
		 * wrap is necessary.
		 *
		 * remove this when Cilium's min supported kernel version is
		 * >= 5.3 with support for bounded loops.
		 */
		if (i < ngrec) {
			rec = &rep->grec[i];

			/* verifier seems to only be happy with a packet bounds check
			 * per iteration
			 */
			if ((void *)rec + sizeof(struct igmpv3_grec) > data_end)
				return DROP_INVALID;

			/* lookup user configured multicast group */
			sub_map = map_lookup_elem(group_map, &rec->grec_mca);
			if (!sub_map)
				continue;

			/* note:
			 * the datapath currently assumes that no source addresses are
			 * present in the exclude message, indicating a join from all
			 * sources message
			 */
			if (rec->grec_type == IGMPV3_CHANGE_TO_EXCLUDE) {
				subscribed = mcast_ipv4_add_subscriber(sub_map, &subscriber);
				if (subscribed != 1)
					return DROP_INVALID;
				continue;
			}

			/* note:
			 * the datapath currently assumes that no source addresses are
			 * present in the include message, indicating a leave from all
			 * sources message
			 */
			if (rec->grec_type == IGMPV3_CHANGE_TO_INCLUDE)
				mcast_ipv4_remove_subscriber(sub_map, &subscriber);
		}
	}
	if (subscribed)
		return DROP_IGMP_SUBSCRIBED;

	return DROP_IGMP_HANDLED;
}

static __always_inline __s32 mcast_ipv4_handle_v2_membership_report(void *ctx,
								    void *group_map,
								    const struct iphdr *ip4,
								    const void *data,
								    const void *data_end)
{
	struct mcast_subscriber_v4 subscriber = {
		.saddr = ip4->saddr,
		.ifindex = ctx_get_ingress_ifindex(ctx)
	};
	int ip_len = ip4->ihl * 4;
	const struct igmphdr *hdr;
	void *sub_map = 0;

	if (data + ETH_HLEN + ip_len + sizeof(struct igmphdr) > data_end)
		return DROP_INVALID;

	hdr = data + ETH_HLEN + ip_len;

	if (hdr->type != IGMPV2_HOST_MEMBERSHIP_REPORT)
		return DROP_INVALID;

	/* lookup user configured multicast group */
	sub_map = map_lookup_elem(group_map, &hdr->group);
	if (!sub_map)
		return DROP_IGMP_HANDLED;

	if (mcast_ipv4_add_subscriber(sub_map, &subscriber))
		return DROP_IGMP_SUBSCRIBED;

	return DROP_IGMP_HANDLED;
}

static __always_inline __s32 mcast_ipv4_handle_igmp_leave(void *group_map,
							  const struct iphdr *ip4,
							  const void *data,
							  const void *data_end)
{
	struct mcast_subscriber_v4 subscriber = {
		.saddr = ip4->saddr,
	};
	int ip_len = ip4->ihl * 4;
	const struct igmphdr *hdr;
	void *sub_map = 0;

	if (data + ETH_HLEN + ip_len + sizeof(struct igmphdr) > data_end)
		return DROP_INVALID;

	hdr = data + ETH_HLEN + ip_len;

	if (hdr->type != IGMP_HOST_LEAVE_MESSAGE)
		return DROP_INVALID;

	/* lookup user configured multicast group */
	sub_map = map_lookup_elem(group_map, &hdr->group);
	if (!sub_map)
		return DROP_IGMP_HANDLED;

	mcast_ipv4_remove_subscriber(sub_map, &subscriber);

	return DROP_IGMP_HANDLED;
}

/* ipv4 igmp handler which dispatches to specific igmp message handlers */
static __always_inline __s32 mcast_ipv4_handle_igmp(void *ctx,
						    struct iphdr *ip4,
						    void *data,
						    void *data_end)
{
	__s32 igmp_type = mcast_ipv4_igmp_type(ip4, data, data_end);

	if (igmp_type < 0)
		return igmp_type;

	switch (igmp_type) {
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		return mcast_ipv4_handle_v3_membership_report(ctx,
							      &cilium_mcast_group_outer_v4_map,
							      ip4,
							      data,
							      data_end);
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		return mcast_ipv4_handle_v2_membership_report(ctx,
							      &cilium_mcast_group_outer_v4_map,
							      ip4,
							      data,
							      data_end);
	case IGMP_HOST_LEAVE_MESSAGE:
		return mcast_ipv4_handle_igmp_leave(&cilium_mcast_group_outer_v4_map,
						    ip4,
						    data,
						    data_end);
	}

	return DROP_IGMP_HANDLED;
}

/* encodes a multicast mac address given a ipv4 group address
 * results are in big endian format and written directly into 'mac'
 */
static __always_inline void mcast_encode_ipv4_mac(union macaddr *mac,
						  const __u8 group[4])
{
	mac->addr[0] = 0x01;
	mac->addr[1] = 0x00;
	mac->addr[2] = 0x0E;
	mac->addr[3] = group[1] & 0x7F;
	mac->addr[4] = group[2];
	mac->addr[5] = group[3];
}

/* callback data used for __mcast_ep_delivery */
struct _mcast_ep_delivery_ctx {
	void *ctx;
	__s32 ret;
};

/* performs packet replication and delivery for multicast traffic egressing
 * an endpoint.
 *
 * to be used as a callback function for bpf_for_each_map_elem
 *
 * callback functions must return 1 or 0 to pass eBPF verifier.
 */
static long __mcast_ep_delivery(__maybe_unused void *sub_map,
				__maybe_unused const __u32 *key,
				const struct mcast_subscriber_v4 *sub,
				struct _mcast_ep_delivery_ctx *cb_ctx)
{
	int ret = 0;
	__u8 from_overlay = 0;
	struct bpf_tunnel_key tun_key = {0};

	if (!cb_ctx || !sub)
		return 1;

	if (!cb_ctx->ctx)
		return 1;

	if (!sub->ifindex)
		return 1;

	from_overlay = (ctx_get_ingress_ifindex(cb_ctx->ctx) == ENCAP_IFINDEX);

	/* set tunnel key for remote delivery
	 * this helper sets the tunnel metadata on the skb_buff but only
	 * tunnel drivers will read it, therefore any local delivery will
	 * simply ignore if its present and deliver without an issue.
	 *
	 * if the ingress interface is set to our tunnel interface, do not
	 * perform delivery, this would cause a loop, since the sender's node
	 * already delivered to all remote nodes.
	 *
	 * checking ctx->ingress_ifindex is reliable since
	 * __netif_receive_skb_core sets the skb's input interface before
	 * calling ingress TC programs.
	 */
	if (sub->flags & MCAST_SUB_F_REMOTE) {
		if (from_overlay)
			return 0;

		tun_key.tunnel_id = 2; /* WORLD ID FOR NOW */
		tun_key.remote_ipv4 = bpf_ntohl(sub->saddr);
		tun_key.tunnel_ttl = IPDEFTTL;

		ret = ctx_set_tunnel_key(cb_ctx->ctx,
					 &tun_key,
					 TUNNEL_KEY_WITHOUT_SRC_IP,
					 BPF_F_ZERO_CSUM_TX);

		if (ret < 0) {
			cb_ctx->ret = ret;
			return 1;
		}
	}

	ret = clone_redirect(cb_ctx->ctx, sub->ifindex, 0);
	if (ret != 0) {
		cb_ctx->ret = ret;
		return 1;
	}
	return 0;
};

/* tailcall to perform multicast packet replication and delivery.
 * when this call is entered we should already know that the packet is destined
 * for a multicast group and the multicast group exists in
 * cilium_mcast_group_outer_v4_map
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_MULTICAST_EP_DELIVERY)
int tail_mcast_ep_delivery(struct __ctx_buff *ctx)
{
	struct _mcast_ep_delivery_ctx cb_ctx = {
		.ctx = ctx,
		.ret = 0
	};
	union macaddr mac = {0};
	void *data, *data_end;
	struct iphdr *ip4 = 0;
	void *sub_map = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	sub_map = map_lookup_elem(&cilium_mcast_group_outer_v4_map, &ip4->daddr);
	if (!sub_map)
		return DROP_INVALID;

	mcast_encode_ipv4_mac(&mac, (__u8 *)&ip4->daddr);

	eth_store_daddr(ctx, &mac.addr[0], 0);

	for_each_map_elem(sub_map, __mcast_ep_delivery, &cb_ctx, 0);

	return send_drop_notify(ctx,
				0,
				0,
				0,
				DROP_MULTICAST_HANDLED,
				CTX_ACT_DROP,
				METRIC_INGRESS);
}

#endif /* ENABLE_MULTICAST */
#endif /* ___LIB_MCAST_H_ */
