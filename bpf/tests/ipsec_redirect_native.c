// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "ipsec_redirect_generic.h"

#include "node_config.h"
#include "lib/encrypt.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/node.h"

PKTGEN("tc", "ipsec_redirect")
int ipsec_redirect_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC,
				      SOURCE_IP, DST_IP);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ipsec_redirect")
int ipsec_redirect_check(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int ret = 0;

	/* for some reason filling maps in a SETUP() function does not work for
	 * this test...
	 */

	/* fill in nodemap entry */
	node_v4_add_entry(DST_NODE_IP, DST_NODE_ID, TARGET_SPI);

	/* fill encrypt map with node's current SPI 3 */
	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&cilium_encrypt_state, &ret, &cfg, BPF_ANY);

	ipcache_v4_add_entry(SOURCE_IP, 0, SOURCE_IDENTITY, 0, BAD_SPI);
	ipcache_v4_add_entry(DST_IP, 0, 0xAC, DST_NODE_IP, TARGET_SPI);

	ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
					      SOURCE_IDENTITY);
	assert(ret == CTX_ACT_REDIRECT);

	/* assert we set the correct mark */
	assert(ctx->mark == TARGET_MARK);

	/* the original source layer 2 address should be the destination for
	 * hairpin redirect
	 */
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("packet too small for eth header");

	struct ethhdr *l2 = data;
	int i;

	for (i = 0; i < 6; i++)
		assert(l2->h_dest[i] = SOURCE_MAC[i]);

	/* ctx_redirect should be called with INGRESS flag for hairpin redirect
	 */
	assert(rec.flags == BPF_F_INGRESS);

	test_finish();
}
