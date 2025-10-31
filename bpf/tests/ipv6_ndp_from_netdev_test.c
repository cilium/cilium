// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/endpoint.h"

#include "scapy.h"

ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})

struct test_args {
	__u32 status_code; /* Only used in generic _check */

	__u8 mac_src[ETH_ALEN];
	__u8 mac_dst[ETH_ALEN];

	union v6addr ip_src;
	union v6addr ip_dst;

	__u8 icmp_type; /* Only used in generic _check */
	union v6addr icmp_ns_addr;
	bool llsrc_opt;
	struct {
		__u8 type;
		__u8 length;
		__u8 llsrc_mac[ETH_ALEN];
	} __packed icmp_opt;
};

/*
 * Generic
 */
static __always_inline
bool __check_ret_code(const struct __ctx_buff *ctx, const __u32 exp_rc)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		return false;

	status_code = data;
	return *status_code == exp_rc;
}

/*
 * These tests make sure that ND packets directed to a Pod IP are answered
 * directly from BPF.
 */

static __always_inline
int __ipv6_from_netdev_ns_pod_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_three, 0, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);

	return netdev_receive_packet(ctx);
}

PKTGEN("tc", "011_ipv6_from_netdev_ns_pod")
int ipv6_from_netdev_ns_pod_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_POD_NS_LLOPT, v6_ndp_pod_ns_llopt);
	BUILDER_PUSH_BUF(builder, V6_NDP_POD_NS_LLOPT);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "011_ipv6_from_netdev_ns_pod")
int ipv6_from_netdev_ns_pod_setup(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_pod_setup(ctx);
}

CHECK("tc", "011_ipv6_from_netdev_ns_pod")
int ipv6_from_netdev_ns_pod_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_REDIRECT));

	BUF_DECL(V6_NDP_POD_NA_LLOPT, v6_ndp_pod_na_llopt);

	ASSERT_CTX_BUF_OFF("pod_na_ns_llopt_ok", "Ether", ctx, sizeof(__u32),
			   V6_NDP_POD_NA_LLOPT,
			   sizeof(BUF(V6_NDP_POD_NA_LLOPT)));
	test_finish();

	return 0;
}

PKTGEN("tc", "011_ipv6_from_netdev_ns_pod_noopt")
int ipv6_from_netdev_ns_pod_pktgen_noopt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_POD_NS, v6_ndp_pod_ns);
	BUILDER_PUSH_BUF(builder, V6_NDP_POD_NS);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "011_ipv6_from_netdev_ns_pod_noopt")
int ipv6_from_netdev_ns_pod_setup_noopt(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_pod_setup(ctx);
}

CHECK("tc", "011_ipv6_from_netdev_ns_pod_noopt")
int ipv6_from_netdev_ns_pod_check_noopt(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_REDIRECT));

	/* Note we always return NA with llopt */
	BUF_DECL(V6_NDP_POD_NA_LLOPT_NS_NOOPT, v6_ndp_pod_na_llopt);
	ASSERT_CTX_BUF_OFF("pod_na_ns_noopt_ok", "Ether", ctx, sizeof(__u32),
			   V6_NDP_POD_NA_LLOPT_NS_NOOPT,
			   sizeof(BUF(V6_NDP_POD_NA_LLOPT_NS_NOOPT)));
	test_finish();

	return 0;
}

/* Bcast NS */

static __always_inline
int __ipv6_from_netdev_ns_pod_setup_mcast(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_pod_three, 0, 0, 0, 0,
			      (__u8 *)mac_three, (__u8 *)mac_two);

	return netdev_receive_packet(ctx);
}

PKTGEN("tc", "012_ipv6_from_netdev_ns_pod_mcast")
int ipv6_from_netdev_ns_pod_pktgen_mcast(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_POD_NS_MCAST_LLOPT, v6_ndp_pod_ns_mcast_llopt);
	BUILDER_PUSH_BUF(builder, V6_NDP_POD_NS_MCAST_LLOPT);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "012_ipv6_from_netdev_ns_pod_mcast")
int ipv6_from_netdev_ns_pod_setup_mcast(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_pod_setup_mcast(ctx);
}

CHECK("tc", "012_ipv6_from_netdev_ns_pod_mcast")
int ipv6_from_netdev_ns_pod_check_mcast(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_REDIRECT));

	/* Note we always return NA with llopt */
	BUF_DECL(V6_NDP_POD_NA_MCAST_NS_NOOPT, v6_ndp_pod_na_llopt);
	ASSERT_CTX_BUF_OFF("pod_na_ns_mcast_ok", "Ether", ctx, sizeof(__u32),
			   V6_NDP_POD_NA_MCAST_NS_NOOPT,
			   sizeof(BUF(V6_NDP_POD_NA_MCAST_NS_NOOPT)));
	test_finish();

	return 0;
}

PKTGEN("tc", "012_ipv6_from_netdev_ns_pod_mcast_noopt")
int ipv6_from_netdev_ns_pod_pktgen_mcast_noopt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_POD_NS_MCAST, v6_ndp_pod_ns_mcast);
	BUILDER_PUSH_BUF(builder, V6_NDP_POD_NS_MCAST);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "012_ipv6_from_netdev_ns_pod_mcast_noopt")
int ipv6_from_netdev_ns_pod_setup_mcast_noopt(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_pod_setup_mcast(ctx);
}

CHECK("tc", "012_ipv6_from_netdev_ns_pod_mcast_noopt")
int ipv6_from_netdev_ns_pod_check_mcast_noopt(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_REDIRECT));

	/* Note we always return NA with llopt */
	BUF_DECL(V6_NDP_POD_NA_MCAST_LLOPT, v6_ndp_pod_na_llopt);
	ASSERT_CTX_BUF_OFF("pod_na_ns_mcast_noopt_ok", "Ether", ctx,
			   sizeof(__u32),
			   V6_NDP_POD_NA_MCAST_LLOPT,
			   sizeof(BUF(V6_NDP_POD_NA_MCAST_LLOPT)));
	test_finish();

	return 0;
}

/*
 * These tests make sure that ND packets directed to the node IP make it
 * to the stack unmodified
 */

/* "Targeted" NS */
static __always_inline
int __ipv6_from_netdev_ns_node_ip_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)v6_node_one, 0, 0, ENDPOINT_F_HOST,
			      0, (__u8 *)mac_three, (__u8 *)mac_two);

	return netdev_receive_packet(ctx);
}

/* With LL SRC option */
PKTGEN("tc", "0211_ipv6_from_netdev_ns_node_ip")
int ipv6_from_netdev_ns_node_ip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_NODE_NS_LLOPT, v6_ndp_node_ns_llopt);
	BUILDER_PUSH_BUF(builder, V6_NDP_NODE_NS_LLOPT);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "0211_ipv6_from_netdev_ns_node_ip")
int ipv6_from_netdev_ns_node_ip_setup(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_node_ip_setup(ctx);
}

CHECK("tc", "0211_ipv6_from_netdev_ns_node_ip")
int ipv6_from_netdev_ns_node_ip_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_OK));

	/* Packet should not be modified */
	BUF_DECL(V6_NDP_NODE_NS_LLOPT_PASS, v6_ndp_node_ns_llopt);
	ASSERT_CTX_BUF_OFF("node_ns_pass", "Ether", ctx,
			   sizeof(__u32),
			   V6_NDP_NODE_NS_LLOPT_PASS,
			   sizeof(BUF(V6_NDP_NODE_NS_LLOPT_PASS)));
	test_finish();

	return 0;
}

/* Without LL SRC option */
PKTGEN("tc", "0212_ipv6_from_netdev_ns_node_ip_noopt")
int ipv6_from_netdev_ns_node_ip_pktgen_noopt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_NODE_NS, v6_ndp_node_ns);
	BUILDER_PUSH_BUF(builder, V6_NDP_NODE_NS);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "0212_ipv6_from_netdev_ns_node_ip_noopt")
int ipv6_from_netdev_ns_node_ip_setup_noopt(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_node_ip_setup(ctx);
}

CHECK("tc", "0212_ipv6_from_netdev_ns_node_ip_noopt")
int ipv6_from_netdev_ns_node_ip_check_noopt(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_OK));

	/* Packet should not be modified */
	BUF_DECL(V6_NDP_NODE_NS_PASS, v6_ndp_node_ns);
	ASSERT_CTX_BUF_OFF("node_ns_pass", "Ether", ctx,
			   sizeof(__u32),
			   V6_NDP_NODE_NS_PASS,
			   sizeof(BUF(V6_NDP_NODE_NS_PASS)));
	test_finish();

	return 0;
}

/* Bcast NS */
static __always_inline
int __ipv6_from_netdev_ns_node_ip_setup_mcast(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)&v6_node_one, 0, 0, ENDPOINT_F_HOST,
			      0, (__u8 *)mac_three, (__u8 *)mac_two);

	return netdev_receive_packet(ctx);
}

PKTGEN("tc", "022_ipv6_from_netdev_ns_node_ip_mcast")
int ipv6_from_netdev_ns_node_ip_pktgen_mcast(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_NODE_NS_MCAST_LLOPT, v6_ndp_node_ns_mcast_llopt);
	BUILDER_PUSH_BUF(builder, V6_NDP_NODE_NS_MCAST_LLOPT);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "022_ipv6_from_netdev_ns_node_ip_mcast")
int ipv6_from_netdev_ns_node_ip_setup_mcast(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_node_ip_setup_mcast(ctx);
}

CHECK("tc", "022_ipv6_from_netdev_ns_node_ip_mcast")
int ipv6_from_netdev_ns_node_ip_check_mcast(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_OK));

	/* Packet should not be modified */
	BUF_DECL(V6_NDP_NODE_NS_MCAST_LLOPT_PASS, v6_ndp_node_ns_mcast_llopt);
	ASSERT_CTX_BUF_OFF("node_ns_mcast_pass", "Ether", ctx,
			   sizeof(__u32),
			   V6_NDP_NODE_NS_MCAST_LLOPT_PASS,
			   sizeof(BUF(V6_NDP_NODE_NS_MCAST_LLOPT_PASS)));
	test_finish();

	return 0;
}

PKTGEN("tc", "022_ipv6_from_netdev_ns_node_ip_mcast_noopt")
int ipv6_from_netdev_ns_node_ip_pktgen_mcast_noopt(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_NDP_NODE_NS_MCAST, v6_ndp_node_ns_mcast);
	BUILDER_PUSH_BUF(builder, V6_NDP_NODE_NS_MCAST);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "022_ipv6_from_netdev_ns_node_ip_mcast_noopt")
int ipv6_from_netdev_ns_node_ip_setup_mcast_noopt(struct __ctx_buff *ctx)
{
	return __ipv6_from_netdev_ns_node_ip_setup_mcast(ctx);
}

CHECK("tc", "022_ipv6_from_netdev_ns_node_ip_mcast_noopt")
int ipv6_from_netdev_ns_node_ip_check_mcast_noopt(const struct __ctx_buff *ctx)
{
	test_init();

	assert(__check_ret_code(ctx, CTX_ACT_OK));

	/* Packet should not be modified */
	BUF_DECL(V6_NDP_NODE_NS_MCAST_PASS, v6_ndp_node_ns_mcast);
	ASSERT_CTX_BUF_OFF("node_ns_mcast_noopt_pass", "Ether", ctx,
			   sizeof(__u32),
			   V6_NDP_NODE_NS_MCAST_PASS,
			   sizeof(BUF(V6_NDP_NODE_NS_MCAST_PASS)));
	test_finish();

	return 0;
}
