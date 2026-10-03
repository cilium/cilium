// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Shared by the service ICMP PMTU relay tests: the include-chain plumbing they
 * all need, the IPv4 test packet, and checksum helpers. Each helper returns the
 * folded checksum over a header (plus pseudo-header where the protocol has
 * one): seeding a zeroed checksum field with the result makes the header valid,
 * and a valid header folds to 0. pktgen does not compute ICMP or embedded-header
 * checksums, and the relay updates them incrementally, so the tests seed valid
 * ones to assert the result.
 */

#pragma once

#include "common.h"
#include "pktgen.h"

/* The relay only compiles into the host/XDP programs. */
#define IS_BPF_HOST
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define ENABLE_SVC_ICMP_PMTU_RELAY

#define TEST_LB_MAGLEV_MAP_MAX_ENTRIES 65536
#define TEST_CONDITIONAL_PREALLOC      0
#define TEST_REVNAT		       1
#define LB_MAGLEV_EXTERNAL

/* Satisfy the nat.h -> egress_gateway.h -> encap.h include chain; the relay
 * itself does not use encap. */
#define ENCAP_IFINDEX	42
#define ENCAP4_IFINDEX	42
#define ENCAP6_IFINDEX	42

static volatile const __u8 pmtu_test_smac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 1};
static volatile const __u8 pmtu_test_dmac[ETH_ALEN] = {0x02, 0, 0, 0, 0, 2};

static __always_inline __u32
pmtu_test_pseudo4(__be32 saddr, __be32 daddr, __u8 proto, __u16 len)
{
	__u32 csum, tmp;

	csum = csum_diff(NULL, 0, &saddr, sizeof(saddr), 0);
	csum = csum_diff(NULL, 0, &daddr, sizeof(daddr), csum);
	tmp = bpf_htonl((__u32)proto);
	csum = csum_diff(NULL, 0, &tmp, sizeof(tmp), csum);
	tmp = bpf_htonl((__u32)len);
	return csum_diff(NULL, 0, &tmp, sizeof(tmp), csum);
}

static __always_inline __sum16
pmtu_test_csum_ip4(const struct iphdr *ip)
{
	return csum_fold(csum_diff(NULL, 0, (void *)ip, sizeof(*ip), 0));
}

/* Embedded TCP header without payload. */
static __always_inline __sum16
pmtu_test_csum_tcp4(const struct iphdr *ip, const struct tcphdr *tcp)
{
	__u32 csum = pmtu_test_pseudo4(ip->saddr, ip->daddr, IPPROTO_TCP,
				       sizeof(*tcp));

	return csum_fold(csum_diff(NULL, 0, (void *)tcp, sizeof(*tcp), csum));
}

static __always_inline __sum16
pmtu_test_csum_tcp6(const struct ipv6hdr *ip6, const struct tcphdr *tcp)
{
	__be32 csum = ipv6_pseudohdr_checksum((struct ipv6hdr *)ip6, IPPROTO_TCP,
					      sizeof(*tcp), 0);

	return csum_fold(csum_diff(NULL, 0, (void *)tcp, sizeof(*tcp), csum));
}

/* ICMPv4 error carrying an embedded IPv4 + TCP header. */
static __always_inline __sum16
pmtu_test_csum_icmp4(const struct icmphdr *icmp, const struct iphdr *inner_ip,
		     const struct tcphdr *inner_tcp)
{
	__u32 csum;

	csum = csum_diff(NULL, 0, (void *)icmp, sizeof(*icmp), 0);
	csum = csum_diff(NULL, 0, (void *)inner_ip, sizeof(*inner_ip), csum);
	csum = csum_diff(NULL, 0, (void *)inner_tcp, sizeof(*inner_tcp), csum);
	return csum_fold(csum);
}

/* ICMPv6 error carrying an embedded IPv6 + TCP header. */
static __always_inline __sum16
pmtu_test_csum_icmp6(const struct ipv6hdr *ip6, const struct icmp6hdr *icmp6,
		     const struct ipv6hdr *inner_ip6, const struct tcphdr *inner_tcp)
{
	__be32 csum = ipv6_pseudohdr_checksum((struct ipv6hdr *)ip6, IPPROTO_ICMPV6,
					      sizeof(*icmp6) + sizeof(*inner_ip6) +
					      sizeof(*inner_tcp), 0);

	csum = csum_diff(NULL, 0, (void *)icmp6, sizeof(*icmp6), csum);
	csum = csum_diff(NULL, 0, (void *)inner_ip6, sizeof(*inner_ip6), csum);
	csum = csum_diff(NULL, 0, (void *)inner_tcp, sizeof(*inner_tcp), csum);
	return csum_fold(csum);
}

/* An ICMPv4 frag-needed from @router to @vip embedding the service's TCP reply
 * vip:svc_port -> client:client_port, with valid checksums throughout. */
static __always_inline int
pmtu_test_pktgen_icmp4(struct __ctx_buff *ctx, __be32 router, __be32 vip,
		       __be32 client, __be16 svc_port, __be16 client_port)
{
	struct pktgen builder;
	struct icmphdr *icmp;
	struct iphdr inner_ip = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_TCP,
		.saddr = vip,
		.daddr = client,
	};
	struct tcphdr inner_tcp = {
		.source = svc_port,
		.dest = client_port,
		.doff = 5,
	};
	struct icmphdr icmp_hdr = {
		.type = ICMP_DEST_UNREACH,
		.code = ICMP_FRAG_NEEDED,
		.un = { .frag = { .mtu = bpf_htons(1400) } },
	};

	pktgen__init(&builder, ctx);
	if (!pktgen__push_ipv4_packet(&builder, (__u8 *)pmtu_test_smac,
				      (__u8 *)pmtu_test_dmac, router, vip))
		return TEST_ERROR;
	icmp = pktgen__push_icmphdr(&builder);
	if (!icmp)
		return TEST_ERROR;

	inner_ip.check = pmtu_test_csum_ip4(&inner_ip);
	inner_tcp.check = pmtu_test_csum_tcp4(&inner_ip, &inner_tcp);
	icmp_hdr.checksum = pmtu_test_csum_icmp4(&icmp_hdr, &inner_ip, &inner_tcp);
	*icmp = icmp_hdr;

	if (!pktgen__push_data(&builder, &inner_ip, sizeof(inner_ip)))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, &inner_tcp, sizeof(inner_tcp)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

struct pmtu_test_pkt4 {
	struct iphdr *ip4;
	struct icmphdr *icmp;
	struct iphdr *inner_ip;
	struct tcphdr *inner_tcp;
};

/* Walk status | eth | ip | icmp | inner ip | inner tcp of a CHECK ctx; false
 * when the packet is truncated. */
static __always_inline bool
pmtu_test_walk4(const struct __ctx_buff *ctx, struct pmtu_test_pkt4 *p)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	p->ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)p->ip4 + sizeof(*p->ip4) > data_end)
		return false;
	p->icmp = (void *)p->ip4 + sizeof(*p->ip4);
	if ((void *)p->icmp + sizeof(*p->icmp) > data_end)
		return false;
	p->inner_ip = (void *)p->icmp + sizeof(*p->icmp);
	if ((void *)p->inner_ip + sizeof(*p->inner_ip) > data_end)
		return false;
	p->inner_tcp = (void *)p->inner_ip + sizeof(*p->inner_ip);
	if ((void *)p->inner_tcp + sizeof(*p->inner_tcp) > data_end)
		return false;
	return true;
}
