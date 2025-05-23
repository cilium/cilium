/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* mock and record calls to ctx_redirect */
struct ctx_redirect_recorder {
	int ifindex;
	__u32 flags;
} rec;
int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		      int ifindex, __u32 flags)
{
	rec.flags = flags;
	rec.ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_IPSEC 1

/* test constants */
#define SOURCE_MAC mac_one
#define DST_MAC mac_two
#define SOURCE_IP v4_pod_one
#define SOURCE_IDENTITY 0xAB
#define DST_IP v4_pod_two
#define DST_NODE_ID 0x08b9
#define DST_NODE_IP v4_node_one
#define TARGET_SPI 2
#define BAD_SPI 3

