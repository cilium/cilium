// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define ENABLE_DSR_BYUSER
#define DSR_ENCAP_MODE DSR_ENCAP_IPIP
#define DSR_ENCAP_IPIP 1

#define ENCAP4_IFINDEX		42
#define ENCAP6_IFINDEX		42

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#include "lib/bpf_host.h"

CHECK("tc", "test_nodeport_uses_dsr_ipv4_with_flag")
int test_nodeport_uses_dsr_ipv4_with_flag(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("nodeport_uses_dsr4 returns true when SVC_FLAG_FWD_MODE_DSR is set", {
		struct lb4_service svc;

		svc.count = 1;
		svc.flags = SVC_FLAG_ROUTABLE;
		svc.flags2 = SVC_FLAG_FWD_MODE_DSR;
		svc.rev_nat_index = 1;

		/* Verify nodeport_uses_dsr4() returns true for DSR-flagged service */
		bool result = nodeport_uses_dsr4(&svc);

		test_log("nodeport_uses_dsr4() with DSR flag: %d (expected: 1)", result);
		if (!result)
			test_error("nodeport_uses_dsr4() should return true with DSR flag");
	})

	TEST("nodeport_uses_dsr4 returns false when SVC_FLAG_FWD_MODE_DSR is not set", {
		struct lb4_service svc;

		svc.count = 1;
		svc.flags = SVC_FLAG_ROUTABLE;
		svc.flags2 = 0;
		svc.rev_nat_index = 2;

		/* Verify nodeport_uses_dsr4() returns false for non-DSR service */
		bool result = nodeport_uses_dsr4(&svc);

		test_log("nodeport_uses_dsr4() without DSR flag: %d (expected: 0)",
			 result);
		if (result)
			test_error("nodeport_uses_dsr4() should return false without DSR flag");
	})

	test_finish();
}

CHECK("tc", "test_nodeport_uses_dsr_ipv6_with_flag")
int test_nodeport_uses_dsr_ipv6_with_flag(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("nodeport_uses_dsr6 returns true when SVC_FLAG_FWD_MODE_DSR is set", {
		struct lb6_service svc;

		svc.count = 1;
		svc.flags = SVC_FLAG_ROUTABLE;
		svc.flags2 = SVC_FLAG_FWD_MODE_DSR;
		svc.rev_nat_index = 3;

		/* Verify nodeport_uses_dsr6() returns true for DSR-flagged service */
		bool result = nodeport_uses_dsr6(&svc);

		test_log("nodeport_uses_dsr6() with DSR flag: %d (expected: 1)", result);
		if (!result)
			test_error("nodeport_uses_dsr6() should return true with DSR flag");
	})

	TEST("nodeport_uses_dsr6 returns false when SVC_FLAG_FWD_MODE_DSR is not set", {
		struct lb6_service svc;

		svc.count = 1;
		svc.flags = SVC_FLAG_ROUTABLE;
		svc.flags2 = 0;
		svc.rev_nat_index = 4;

		/* Verify nodeport_uses_dsr6() returns false for non-DSR service */
		bool result = nodeport_uses_dsr6(&svc);

		test_log("nodeport_uses_dsr6() without DSR flag: %d (expected: 0)",
			 result);
		if (result)
			test_error("nodeport_uses_dsr6() should return false without DSR flag");
	})

	test_finish();
}
