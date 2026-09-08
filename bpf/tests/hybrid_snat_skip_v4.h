/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_NODEPORT 1
#define ENCAP_IFINDEX 1
#define TUNNEL_MODE 1
#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1

#include "nodeport_defaults.h"
#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = v4_node_one })
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, ENABLE_REMOTE_NODE_MASQUERADE)
ASSIGN_CONFIG(bool, hybrid_routing_enabled, ENABLE_HYBRID_ROUTING)

#include "lib/clear.h"
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/subnet.h"

static __always_inline int
hybrid_snat_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);
	if (!pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_node_two,
					  tcp_src_one, tcp_svc_two))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
hybrid_snat_v4_setup(struct __ctx_buff *ctx, __u32 src_subnet_id, __u32 dst_subnet_id)
{
	struct subnet_key key = {
		.lpm_key = { .prefixlen = SUBNET_PREFIX_LEN(V4_SUBNET_KEY_LEN) },
		.family = ENDPOINT_KEY_IPV4,
	};

	/* Each case uses the same flow. Reset CT/NAT state so a preceding case
	 * cannot determine whether this packet is masqueraded.
	 */
	clear_map(&cilium_ct4_global);
	clear_map(&cilium_ct_any4_global);
	clear_map(get_cluster_snat_map_v4(0));

	/* Remove both LPM entries explicitly: a zero ID models a lookup miss,
	 * including when a previous case installed a non-zero ID.
	 */
	key.ip4.be32 = v4_pod_one;
	map_delete_elem(&cilium_subnet_map, &key);
	key.ip4.be32 = v4_node_two;
	map_delete_elem(&cilium_subnet_map, &key);
	if (src_subnet_id)
		subnet_v4_add_entry(v4_pod_one, src_subnet_id);
	if (dst_subnet_id)
		subnet_v4_add_entry(v4_node_two, dst_subnet_id);

	ipcache_v4_add_entry(v4_node_two, 0, REMOTE_NODE_ID, 0, 0);
	endpoint_v4_add_entry(v4_pod_one, 0, 0, 0, 0, 0, NULL, NULL);

	return netdev_send_packet(ctx);
}

static __always_inline int
hybrid_snat_v4_check(const struct __ctx_buff *ctx, bool snat)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u32 csum, pseudo;
	__u8 *payload;

	test_init();

	if ((void *)(status_code + 1) > data_end)
		test_fatal("status code out of bounds");
	assert(*status_code == CTX_ACT_OK);

	eth = (void *)(status_code + 1);
	if ((void *)(eth + 1) > data_end)
		test_fatal("Ethernet header out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(memcmp(eth->h_source, (__u8 *)mac_one, ETH_ALEN) == 0);
	assert(memcmp(eth->h_dest, (__u8 *)mac_two, ETH_ALEN) == 0);

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		test_fatal("IP header out of bounds");
	assert(ip->saddr == (snat ? CONFIG(nat_ipv4_masquerade).be32 : v4_pod_one));
	assert(ip->daddr == v4_node_two);
	assert(ip->protocol == IPPROTO_TCP);
	assert(csum_fold(csum_diff(NULL, 0, ip, sizeof(*ip), 0)) == 0);

	tcp = (void *)(ip + 1);
	if ((void *)(tcp + 1) > data_end)
		test_fatal("TCP header out of bounds");
	if (snat) {
		assert(bpf_ntohs(tcp->source) >= NODEPORT_PORT_MIN_NAT);
		assert(bpf_ntohs(tcp->source) <= NODEPORT_PORT_MAX_NAT);
	} else {
		assert(tcp->source == tcp_src_one);
	}
	assert(tcp->dest == tcp_svc_two);

	payload = (void *)(tcp + 1);
	if ((void *)payload + sizeof(default_data) > data_end)
		test_fatal("payload out of bounds");
	assert(memcmp(payload, default_data, sizeof(default_data)) == 0);

	/* Validate the TCP checksum against the resulting IP pseudo-header,
	 * including when SNAT changed the address and source port.
	 */
	csum = csum_diff(NULL, 0, &ip->saddr, sizeof(ip->saddr), 0);
	csum = csum_diff(NULL, 0, &ip->daddr, sizeof(ip->daddr), csum);
	pseudo = bpf_htonl(IPPROTO_TCP);
	csum = csum_diff(NULL, 0, &pseudo, sizeof(pseudo), csum);
	pseudo = bpf_htonl(sizeof(*tcp) + sizeof(default_data));
	csum = csum_diff(NULL, 0, &pseudo, sizeof(pseudo), csum);
	csum = csum_diff(NULL, 0, tcp, sizeof(*tcp) + sizeof(default_data), csum);
	assert(csum_fold(csum) == 0);

	test_finish();
}
