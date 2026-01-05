// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_LOCAL	v4_svc_one
#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_IP_ETP_LOCAL	v4_svc_three
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP_LOCAL	v4_pod_one
#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE	24

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;
static volatile const __u8 *remote_backend_mac = mac_five;

#include <bpf/compiler.h>
#include <bpf/helpers.h>
#include <bpf/loader.h>
#include <bpf/section.h>
#include <linux/bpf.h>
#include <linux/types.h>

struct mock_settings {
	__be16 nat_source_port;
	bool fail_fib;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings && settings->fail_fib) {
		params->ifindex = DEFAULT_IFACE;
		return BPF_FIB_LKUP_RET_NO_NEIGH;
	}

	params->ifindex = 0;

	if (params->ipv4_dst == BACKEND_IP_REMOTE) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	return 0;
}

#include "lib/bpf_xdp.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/network_device.h"

/* Test that a SVC request to a local backend
 * - gets DNATed (but not SNATed)
 * - gets passed up from XDP to TC
 */
PKTGEN("xdp", "xdp_nodeport_local_backend")
int nodeport_local_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_nodeport_local_backend")
int nodeport_local_backend_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_LOCAL, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_LOCAL, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	/* add local backend */
	endpoint_v4_add_entry(BACKEND_IP_LOCAL, 0, 0, 0, 0, 0,
			      (__u8 *)local_backend_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(BACKEND_IP_LOCAL, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_local_backend")
int nodeport_local_backend_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 *meta;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	status_code = data;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	meta = (void *)status_code + sizeof(__u32);
	if ((void *)meta + sizeof(__u32) > data_end)
		test_fatal("meta out of bounds");

	l2 = (void *)meta + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert(*status_code == CTX_ACT_OK);

	assert((*meta & XFER_PKT_NO_SVC) == XFER_PKT_NO_SVC);

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the LB MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dst IP hasn't been NATed to local backend IP");

	if (l3->check != bpf_htons(0x4112))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port hasn't been NATed to backend port");

	if (l4->check != bpf_htons(0xd7d0))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that a eTP=local SVC request
 * - gets passed up from XDP to TC without DNAT,
 * - doesn't have the XFER_PKT_NO_SVC flag set, so that the TC layer applies
 *   another round of SVC processing
 */
PKTGEN("xdp", "xdp_nodeport_etp_local")
int nodeport_etp_local_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_ETP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_nodeport_etp_local")
int nodeport_etp_local_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service_with_flags(FRONTEND_IP_ETP_LOCAL, FRONTEND_PORT,
				     IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_EXT_LOCAL_SCOPE,
				     0);
	lb_v4_add_backend(FRONTEND_IP_ETP_LOCAL, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_etp_local")
int nodeport_etp_local_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	status_code = data;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* No meta information transferred. */

	l2 = (void *)status_code + sizeof(__u32);
	if ((void *)status_code + sizeof(__u32) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert(*status_code == CTX_ACT_OK);

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the LB MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != FRONTEND_IP_ETP_LOCAL)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != FRONTEND_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

/* Test that a SVC request that is LBed to a NAT remote backend
 * - gets DNATed and SNATed,
 * - gets redirected back out by XDP
 */
PKTGEN("xdp", "xdp_nodeport_nat_fwd")
int nodeport_nat_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("xdp", "xdp_nodeport_nat_fwd")
int nodeport_nat_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_nat_fwd")
int nodeport_nat_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

static __always_inline int build_reply(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;
	__u16 nat_source_port = 0;
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings && settings->nat_source_port)
		nat_source_port = settings->nat_source_port;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)remote_backend_mac, (__u8 *)lb_mac,
					  BACKEND_IP_REMOTE, LB_IP,
					  BACKEND_PORT, nat_source_port);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline int check_reply(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (l3->saddr != FRONTEND_IP_REMOTE)
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP hasn't been RevNATed to client IP");

	if (l3->check != bpf_htons(0x4ca9))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port hasn't been RevNATed to client port");

	if (l4->check != bpf_htons(0x01a8))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 */
PKTGEN("xdp", "xdp_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("xdp", "xdp_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_setup(struct __ctx_buff *ctx)
{
	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_nat_fwd_reply")
int nodeport_nat_fwd_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* Test that the LB RevDNATs and RevSNATs a reply from the
 * NAT remote backend, and sends it back to the client.
 * Even if the FIB lookup fails.
 */
PKTGEN("xdp", "xdp_nodeport_nat_fwd_reply_no_fib")
int nodepoirt_nat_fwd_reply_no_fib_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("xdp", "xdp_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_setup(struct __ctx_buff *ctx)
{
	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->fail_fib = true;

	cilium_device_add_entry(DEFAULT_IFACE, (__u8 *)lb_mac, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_nat_fwd_reply_no_fib")
int nodeport_nat_fwd_reply_no_fib_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

/* Test that a L7 delegate SVC request
 * - gets passed up from XDP to TC without DNAT,
 * - does have XFER_PKT_NO_SVC flag set so that TC does not process it again
 * if the backend is a /local/ backend
 */
PKTGEN("xdp", "xdp_nodeport_l7delegate_local")
int nodeport_l7delegate_local_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_ETP_LOCAL,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("xdp", "xdp_nodeport_l7delegate_local")
int nodeport_l7delegate_local_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service_with_flags(FRONTEND_IP_ETP_LOCAL, FRONTEND_PORT,
				     IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
				     SVC_FLAG_L7_DELEGATE);

	lb_v4_add_backend(FRONTEND_IP_ETP_LOCAL, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_LOCAL, BACKEND_PORT, IPPROTO_TCP, 0);

	endpoint_v4_add_entry(BACKEND_IP_LOCAL, 0, 0, ENDPOINT_F_HOST, 1,
			      0, NULL, NULL);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_l7delegate_local")
int nodeport_l7delegate_local_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 *meta;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	status_code = data;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	meta = (void *)status_code + sizeof(__u32);
	if ((void *)meta + sizeof(__u32) > data_end)
		test_fatal("meta out of bounds");

	l2 = (void *)meta + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert(*status_code == CTX_ACT_OK);

	assert((*meta & XFER_PKT_NO_SVC) == XFER_PKT_NO_SVC);

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")
	if (memcmp(l2->h_dest, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the LB MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != FRONTEND_IP_ETP_LOCAL)
		test_fatal("dst IP has changed");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != FRONTEND_PORT)
		test_fatal("dst port has changed");

	test_finish();
}

/* Test that a L7 delegate SVC request
 * - performs DNAT to the remote destination,
 * - does not have XFER_PKT_NO_SVC flag set
 * if the backend is a /remote/ backend. Similar test as the
 * xdp_nodeport_l7delegate_local just that the backend is not
 * part of the endpoint map.
 */
PKTGEN("xdp", "xdp_nodeport_l7delegate_remote")
int nodeport_l7delegate_remote_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("xdp", "xdp_nodeport_l7delegate_remote")
int nodeport_l7delegate_remote_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service_with_flags(FRONTEND_IP_REMOTE, FRONTEND_PORT,
				     IPPROTO_TCP, 1, revnat_id,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_LOADBALANCER,
				     SVC_FLAG_L7_DELEGATE);

	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, 0, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_l7delegate_remote")
int nodeport_l7delegate_remote_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(fib_ok(*status_code));

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the LB MAC")
	if (memcmp(l2->h_dest, (__u8 *)remote_backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != LB_IP)
		test_fatal("src IP hasn't been NATed to LB IP");

	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dst IP hasn't been NATed to remote backend IP");

	if (l3->check != bpf_htons(0xa711))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->source == CLIENT_PORT)
		test_fatal("src port hasn't been NATed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been NATed to backend port");

	test_finish();
}
