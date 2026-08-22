// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_SIP_VERIFICATION

#define CLIENT_IP		v6_pod_one_addr
/* Link-local address the kernel assigns to the pod interface. */
#define CLIENT_LL_IP		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, \
				 0x1c, 0x05, 0xa0, 0xff, 0xfe, 0xe1, 0xf9, 0xa6}
#define SERVER_IP		v6_pod_two_addr
#define ALL_ROUTERS_IP		{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
#define ALL_MLDV2_ROUTERS_IP	{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *gw_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = CLIENT_IP })

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

/* The kernel sends MLD messages with a hop by hop options header that carries
 * the router alert option, so the ICMPv6 header does not directly follow the
 * IPv6 header. Build that layout when with_router_alert is set.
 */
static __always_inline int
build_icmp6(struct __ctx_buff *ctx, __u8 *saddr, __u8 *daddr, __u8 type,
	    bool with_router_alert)
{
	struct pktgen builder;
	struct icmp6hdr *l4;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ipv6_packet(&builder,
				      (__u8 *)client_mac, (__u8 *)gw_mac,
				      saddr, daddr))
		return TEST_ERROR;

	if (with_router_alert &&
	    !pktgen__append_ipv6_extension_header(&builder, NEXTHDR_HOP, 0))
		return TEST_ERROR;

	l4 = pktgen__push_icmp6hdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->icmp6_type = type;
	l4->icmp6_code = 0;
	l4->icmp6_cksum = 0;

	pktgen__finish(&builder);

	return 0;
}

/* Give the pod everything it needs to have its traffic forwarded, so that a
 * packet only gets dropped if it fails the source IP check.
 */
static __always_inline int
send_from_pod(struct __ctx_buff *ctx)
{
	union v6addr client_ip = { .addr = CLIENT_IP };

	policy_add_egress_allow_all_entry();
	endpoint_v6_add_entry(&client_ip, 0, LXC_ID, 0, 0,
			      (__u8 *)client_mac, (__u8 *)client_mac);
	ipcache_v6_add_entry(&client_ip, 0, LXC_ID, 0, 0);
	ipcache_v6_add_world_entry();

	set_identity_mark(ctx, LXC_ID, MARK_MAGIC_IDENTITY);

	return pod_send_packet(ctx);
}

static __always_inline int
read_status_code(const struct __ctx_buff *ctx, __u32 *status_code)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return -1;

	*status_code = *(__u32 *)data;

	return 0;
}

static __always_inline void
clean_up(void)
{
	union v6addr client_ip = { .addr = CLIENT_IP };

	endpoint_v6_del_entry(&client_ip);
	policy_delete_egress_all_entry();
}

/* Router solicitation from the link-local address to ff02::2. */
PKTGEN("tc", "lxc_icmp6_ll_router_solicitation")
int lxc_icmp6_ll_router_solicitation_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = CLIENT_LL_IP;
	__u8 daddr[] = ALL_ROUTERS_IP;

	return build_icmp6(ctx, saddr, daddr, ICMP6_RS_MSG_TYPE, false);
}

SETUP("tc", "lxc_icmp6_ll_router_solicitation")
int lxc_icmp6_ll_router_solicitation_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_ll_router_solicitation")
int lxc_icmp6_ll_router_solicitation_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_OK);

	clean_up();

	test_finish();
}

/* MLDv2 report from the link-local address, which the kernel sends on its
 * own every few seconds. It carries a router alert hop by hop header.
 */
PKTGEN("tc", "lxc_icmp6_ll_mld_report")
int lxc_icmp6_ll_mld_report_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = CLIENT_LL_IP;
	__u8 daddr[] = ALL_MLDV2_ROUTERS_IP;

	return build_icmp6(ctx, saddr, daddr, ICMP6_MLD2_REPORT_MSG_TYPE, true);
}

SETUP("tc", "lxc_icmp6_ll_mld_report")
int lxc_icmp6_ll_mld_report_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_ll_mld_report")
int lxc_icmp6_ll_mld_report_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_OK);

	clean_up();

	test_finish();
}

/* Same report, sent while the link-local address is still tentative. */
PKTGEN("tc", "lxc_icmp6_unspec_mld_report")
int lxc_icmp6_unspec_mld_report_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = v6_all_addr;
	__u8 daddr[] = ALL_MLDV2_ROUTERS_IP;

	return build_icmp6(ctx, saddr, daddr, ICMP6_MLD2_REPORT_MSG_TYPE, true);
}

SETUP("tc", "lxc_icmp6_unspec_mld_report")
int lxc_icmp6_unspec_mld_report_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_unspec_mld_report")
int lxc_icmp6_unspec_mld_report_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_OK);

	clean_up();

	test_finish();
}

/* An echo request gets no exemption, even from the link-local address. */
PKTGEN("tc", "lxc_icmp6_ll_echo_request")
int lxc_icmp6_ll_echo_request_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = CLIENT_LL_IP;
	__u8 daddr[] = ALL_ROUTERS_IP;

	return build_icmp6(ctx, saddr, daddr, ICMPV6_ECHO_REQUEST, false);
}

SETUP("tc", "lxc_icmp6_ll_echo_request")
int lxc_icmp6_ll_echo_request_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_ll_echo_request")
int lxc_icmp6_ll_echo_request_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_DROP);

	clean_up();

	test_finish();
}

/* Neither does a router solicitation aimed at a pod address. */
PKTGEN("tc", "lxc_icmp6_ll_unicast_router_solicitation")
int lxc_icmp6_ll_unicast_router_solicitation_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = CLIENT_LL_IP;
	__u8 daddr[] = SERVER_IP;

	return build_icmp6(ctx, saddr, daddr, ICMP6_RS_MSG_TYPE, false);
}

SETUP("tc", "lxc_icmp6_ll_unicast_router_solicitation")
int lxc_icmp6_ll_unicast_router_solicitation_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_ll_unicast_router_solicitation")
int lxc_icmp6_ll_unicast_router_solicitation_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_DROP);

	clean_up();

	test_finish();
}

/* A pod sending a router advertisement is pretending to be a router, so the
 * packet stays dropped.
 */
PKTGEN("tc", "lxc_icmp6_ll_router_advertisement")
int lxc_icmp6_ll_router_advertisement_pktgen(struct __ctx_buff *ctx)
{
	__u8 saddr[] = CLIENT_LL_IP;
	__u8 daddr[] = ALL_ROUTERS_IP;

	return build_icmp6(ctx, saddr, daddr, ICMP6_RA_MSG_TYPE, false);
}

SETUP("tc", "lxc_icmp6_ll_router_advertisement")
int lxc_icmp6_ll_router_advertisement_setup(struct __ctx_buff *ctx)
{
	return send_from_pod(ctx);
}

CHECK("tc", "lxc_icmp6_ll_router_advertisement")
int lxc_icmp6_ll_router_advertisement_check(const struct __ctx_buff *ctx)
{
	__u32 status_code;

	test_init();

	if (read_status_code(ctx, &status_code))
		test_fatal("status code out of bounds");

	assert(status_code == CTX_ACT_DROP);

	clean_up();

	test_finish();
}
