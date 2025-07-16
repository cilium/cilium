// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_MASQUERADE_IPV6		1
#define ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY

/* Test IPv6 addresses and values */
#define CLIENT_IP		v6_ext_node_one  /* 2001::1 */
#define CLUSTERIP_IP		v6_pod_one       /* fd04::1 */
#define SERVICE_PORT		tcp_svc_one
#define BACKEND_IP		v6_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define ICMP6_ID		__bpf_htons(0x1234)
#define ICMP6_SEQ		__bpf_htons(0x0001)

/* Expected checksums for ICMPv6 echo reply:
 * CLIENT_IP: 2001::1 (v6_ext_node_one)
 * CLUSTERIP_IP: fd04::1 (v6_pod_one)
 *
 * ICMPv6 checksum calculation includes (RFC 4443 Section 2.3):
 * - IPv6 pseudo-header: src addr (16), dst addr (16), length (4), next header (4)
 * - ICMPv6 header: type=129, code=0, id=0x1234, seq=0x0001
 * - Data payload: 20 bytes of default_data pattern
 *
 * From packet dump:
 * - ICMPv6 message length: 28 bytes
 * - Pseudo-header: fd04::1 + 2001::1 + 0x1c + 0x3a
 * - ICMPv6 words: 8100 0000 1234 0001 + data pattern
 * - Empirically validated checksum: 0x12fa
 */
#define EXPECTED_ICMP6_CHECKSUM	0x12fa  /* Empirically validated checksum */

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x57 };

#include <bpf_host.c>

ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, {.addr = v6_node_one_addr})

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test ICMPv6 echo reply checksum validation against known good values */
PKTGEN("tc", "tc_icmp6_checksum_validation")
int icmp6_checksum_validation_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6hdr;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv6 header */
	l3 = pktgen__push_default_ipv6hdr(&builder);
	if (!l3)
		return TEST_ERROR;

	memcpy(&l3->saddr, (__u8 *)&CLIENT_IP, 16);
	memcpy(&l3->daddr, (__u8 *)&CLUSTERIP_IP, 16);

	/* Push ICMPv6 header */
	icmp6hdr = pktgen__push_icmp6hdr(&builder);
	if (!icmp6hdr)
		return TEST_ERROR;

	icmp6hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6hdr->icmp6_code = 0;
	icmp6hdr->icmp6_identifier = ICMP6_ID;
	icmp6hdr->icmp6_sequence = ICMP6_SEQ;

	/* Add data payload */
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calculate checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_icmp6_checksum_validation")
int icmp6_checksum_validation_setup(struct __ctx_buff *ctx)
{
	/* Add ipcache entry for client IP to fix "Failed to map addr" error */
	ipcache_v6_add_entry((union v6addr *)&CLIENT_IP, 0, WORLD_IPV6_ID, 0, 0);

	/* Create a ClusterIP service which will automatically get a wildcard entry
	 * for ICMPv6 echo reply handling due to ENABLE_VIRTUAL_IP_ICMP_ECHO_REPLY
	 */
	lb_v6_add_service_with_flags((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, IPPROTO_TCP, 1, 1, 0, 0);

	/* Add a backend for the service */
	lb_v6_add_backend((union v6addr *)&CLUSTERIP_IP, SERVICE_PORT, 1, 1, (union v6addr *)&BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_icmp6_checksum_validation")
int icmp6_checksum_validation_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *icmp6hdr;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	test_log("Status code: %d, expected: %d (CTX_ACT_REDIRECT)", *status_code, CTX_ACT_REDIRECT);
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Parse ethernet header */
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	assert(l2->h_proto == bpf_htons(ETH_P_IPV6));

	/* Parse IPv6 header */
	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	assert(l3->nexthdr == IPPROTO_ICMPV6);

	/* Parse ICMPv6 header */
	icmp6hdr = data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	if ((void *)icmp6hdr + sizeof(struct icmp6hdr) > data_end)
		test_fatal("icmp6hdr out of bounds");

	/* Verify this is an ICMPv6 echo reply */
	test_log("ICMPv6 type: %d, expected: %d (ICMPV6_ECHO_REPLY)", icmp6hdr->icmp6_type, ICMPV6_ECHO_REPLY);
	assert(icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY);

	/* Verify ICMPv6 ID and sequence are preserved */
	assert(icmp6hdr->icmp6_identifier == ICMP6_ID);
	assert(icmp6hdr->icmp6_sequence == ICMP6_SEQ);

	/* Verify addresses are swapped */
	test_log("Checking IPv6 address swapping: src should be CLUSTERIP_IP, dst should be CLIENT_IP");
	assert(memcmp(&l3->saddr, (__u8 *)&CLUSTERIP_IP, 16) == 0);
	assert(memcmp(&l3->daddr, (__u8 *)&CLIENT_IP, 16) == 0);
	test_log("IPv6 address swapping verified successfully");

	/* Verify hop limit is set to default (64) */
	test_log("Hop limit: %d, expected: 64", l3->hop_limit);
	assert(l3->hop_limit == 64);

	/* Dump the IPv6 header for analysis */
	test_log("IPv6 header dump:");
	test_log("  version: %d, priority: %d", l3->version, l3->priority);
	test_log("  payload_len: %d, nexthdr: %d", __bpf_ntohs(l3->payload_len), l3->nexthdr);
	test_log("  hop_limit: %d", l3->hop_limit);

	/* Dump the ICMPv6 header for analysis */
	test_log("ICMPv6 header dump:");
	test_log("  type: %x, code: %x", icmp6hdr->icmp6_type, icmp6hdr->icmp6_code);
	test_log("  checksum: %x", __bpf_ntohs(icmp6hdr->icmp6_cksum));
	test_log("  id: %x, seq: %x", __bpf_ntohs(icmp6hdr->icmp6_identifier),
		 __bpf_ntohs(icmp6hdr->icmp6_sequence));

	/* Dump the ICMPv6 data for manual checksum calculation */
	test_log("ICMPv6 message (header + data) dump for checksum calculation:");

	/* Calculate ICMPv6 message length */
	__u32 icmp6_len = __bpf_ntohs(l3->payload_len);
	test_log("ICMPv6 message length: %d bytes", icmp6_len);

	/* Dump ICMPv6 message as 16-bit words */
	__u16 *icmp6_words = (__u16 *)icmp6hdr;
	__u32 num_words = (icmp6_len + 1) / 2; /* Round up for odd lengths */

	test_log("ICMPv6 words for checksum (first 40 words):");
	for (__u32 i = 0; i < num_words && i < 40; i++) { /* Limit output */
		if ((void *)(icmp6_words + i + 1) > data_end)
			break;
		__u16 word_val = __bpf_ntohs(icmp6_words[i]);
		test_log("  word[%d]: %x", i, word_val);
	}

	/* Dump pseudo-header components for checksum verification */
	test_log("IPv6 pseudo-header for checksum calculation:");
	test_log("  Source address: service IP (16 bytes)");
	test_log("  Destination address: client IP (16 bytes)");
	test_log("  ICMPv6 length: %d (0x%x)", icmp6_len, icmp6_len);
	test_log("  Next header: %d (0x%x = ICMPv6)", IPPROTO_ICMPV6, IPPROTO_ICMPV6);

	/* CRITICAL: Verify ICMPv6 checksum - show what BPF code produced */
	test_log("ICMPv6 checksum: %x (expected: %x)",
		 __bpf_ntohs(icmp6hdr->icmp6_cksum), EXPECTED_ICMP6_CHECKSUM);
	/* This will fail and show us what the BPF code actually produces */
	assert(__bpf_ntohs(icmp6hdr->icmp6_cksum) == EXPECTED_ICMP6_CHECKSUM);



	/* Additional validation: Verify MAC addresses are swapped */
	test_log("Checking MAC address swapping: src should be lb_mac, dst should be client_mac");
	assert(memcmp(l2->h_source, (__u8 *)lb_mac, ETH_ALEN) == 0);
	assert(memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) == 0);
	test_log("MAC address swapping verified successfully");

	test_finish();
}
