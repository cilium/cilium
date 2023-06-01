// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/ctx/xdp.h"
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_NODEPORT_ACCELERATION
#define ENABLE_SESSION_AFFINITY

/* Make sure we always pick backend slot 1 if we end up in backend selection. */
#define LB_SELECTION LB_SELECTION_FIRST

#define fib_lookup mock_fib_lookup

static const char fib_smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
static const char fib_dmac[6] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, fib_smac, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, fib_dmac, ETH_ALEN);
	return 0;
}

#include "bpf_xdp.c"
#include "lib/nodeport.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_xdp_entry,
	},
};

#define CLIENT_IP IPV4(10, 0, 0, 1)
#define FRONTEND_IP IPV4(10, 0, 1, 1)
#define BACKEND_IP1 IPV4(10, 0, 2, 1)
#define BACKEND_IP2 IPV4(10, 0, 3, 1)
#define FRONTEND_PORT bpf_htons(80)
#define BACKEND_PORT bpf_htons(8080)
#define REV_NAT_INDEX 123
#define BACKEND_ID1 7
#define BACKEND_ID2 42

static __always_inline int craft_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	pktgen__init(&builder, ctx);

	eh = pktgen__push_ethhdr(&builder);
	if (!eh)
		return TEST_ERROR;
	*eh = (struct ethhdr){.h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			      .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
			      .h_proto = bpf_htons(ETH_P_IP)};

	iph = pktgen__push_default_iphdr(&builder);

	if (!iph)
		return TEST_ERROR;

	iph->saddr = CLIENT_IP;
	iph->daddr = FRONTEND_IP;

	tcph = pktgen__push_default_tcphdr(&builder);
	if (!tcph)
		return TEST_ERROR;

	tcph->source = bpf_htons(23445);
	tcph->dest = FRONTEND_PORT;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

#define SVC_KEY_VALUE(_beslot, _beid, _scope)				\
	{								\
		.key = {.address = FRONTEND_IP,				\
			.dport = FRONTEND_PORT,				\
			.scope = (_scope),				\
			.backend_slot = (_beslot)},			\
		.value = {						\
			.flags = SVC_FLAG_ROUTABLE | SVC_FLAG_AFFINITY, \
			.count = 2,					\
			.rev_nat_index = REV_NAT_INDEX,			\
			.backend_id = (_beid)				\
		}							\
	}

#define BE_KEY_VALUE(_beid, _beip)		\
	{					\
		.key = (_beid),			\
		.value = {.address = (_beip),	\
			  .port = BACKEND_PORT, \
			  .proto = IPPROTO_TCP},\
	}

SETUP("xdp", "session_affinity")
int test1_setup(struct __ctx_buff *ctx)
{
	struct {
		struct lb4_key key;
		struct lb4_service value;
	} services[] = {
		SVC_KEY_VALUE(0, 100 /* affinity timeout */, LB_LOOKUP_SCOPE_INT),
		SVC_KEY_VALUE(0, 100 /* affinity timeout */, LB_LOOKUP_SCOPE_EXT),

		SVC_KEY_VALUE(1, BACKEND_ID1, LB_LOOKUP_SCOPE_EXT),
		SVC_KEY_VALUE(2, BACKEND_ID2, LB_LOOKUP_SCOPE_EXT),
	};
	struct {
		__u32 key;
		struct lb4_backend value;
	} backends[] = {
		BE_KEY_VALUE(BACKEND_ID1, BACKEND_IP1),
		BE_KEY_VALUE(BACKEND_ID2, BACKEND_IP2),
	};
	struct lb4_affinity_key aff_key = {
		.client_id = {.client_ip = CLIENT_IP},
		.rev_nat_id = REV_NAT_INDEX,
		.netns_cookie = 0x0,
	};
	struct lb_affinity_val aff_value = {
		.last_used = bpf_mono_now(),
		.backend_id = BACKEND_ID2,
	};
	struct lb_affinity_match match_key = {
		.backend_id = BACKEND_ID2,
		.rev_nat_id = REV_NAT_INDEX,
	};
	int ret;
	int zero = 0;

	/* Insert the service and backend map values */
	for (unsigned long i = 0; i < ARRAY_SIZE(services); i++) {
		map_update_elem(&LB4_SERVICES_MAP_V2, &services[i].key,
				&services[i].value, BPF_ANY);
	}

	for (unsigned long i = 0; i < ARRAY_SIZE(backends); i++) {
		map_update_elem(&LB4_BACKEND_MAP, &backends[i].key,
				&backends[i].value, BPF_ANY);
	}

	/* Create the session affinity entry for the client */
	map_update_elem(&LB4_AFFINITY_MAP, &aff_key, &aff_value, BPF_ANY);

	/* Add the affinity match entry to mark the backend as alive */
	map_update_elem(&LB_AFFINITY_MATCH_MAP, &match_key, &zero, BPF_ANY);

	ret = craft_packet(ctx);
	if (ret)
		return ret;

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("xdp", "session_affinity")
int test1_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 *status_code = data;

	if (*status_code != XDP_TX) test_fatal("status code != XDP_TX %d", *status_code);

	data += sizeof(__u32);

	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("ctx doesn't fit ethhdr");

	struct ethhdr *l2 = data;

	data += sizeof(struct ethhdr);

	if (memcmp(l2->h_source, fib_smac, sizeof(fib_smac)) != 0)
		test_fatal("l2->h_source != fib_smac");

	if (memcmp(l2->h_dest, fib_dmac, sizeof(fib_dmac)) != 0)
		test_fatal("l2->h_dest != fib_dmac");

	if (data + sizeof(struct iphdr) > data_end)
		test_fatal("ctx doesn't fit iphdr");

	struct iphdr *l3 = data;

	data += sizeof(struct iphdr);

	if (l3->daddr != BACKEND_IP2) test_fatal("dst ip != backend IP");

	if (data + sizeof(struct tcphdr) > data_end)
		test_fatal("ctx doesn't fit tcphdr");

	struct tcphdr *l4 = data;

	data += sizeof(struct tcphdr);

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port changed");

	test_finish();
}
