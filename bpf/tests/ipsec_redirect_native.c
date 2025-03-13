// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "ipsec_redirect_generic.h"

#include "node_config.h"
#include "lib/encrypt.h"
#include "tests/lib/ipcache.h"

PKTGEN("tc", "ipsec_redirect")
int ipsec_redirect_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)SOURCE_MAC, (__u8 *)DST_MAC);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = SOURCE_IP;
	l3->daddr = DST_IP;

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
	struct node_key key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_IP,
	};
	struct node_value val = {
		.id = DST_NODE_ID,
		.spi = TARGET_SPI, /* we should find spi 2 in mark since we use lowest */
	};
	map_update_elem(&NODE_MAP_V2, &key, &val, BPF_ANY);

	/* fill encrypt map with node's current SPI 3 */
	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&ENCRYPT_MAP, &ret, &cfg, BPF_ANY);

	/* fill in IPCache entries, SPI should be retrieved from node map so
	 * make them null
	 */
	ipcache_v4_add_entry(SOURCE_IP, 0, 0xAB, 0, 0);
	/* this IPcache fill is not a representation of how things work during
	 * Cilium runtime, a IPCache entry would not point to itself as its
	 * tunnel_endpoint, this just makes the test a bit simpler.
	 * The tunnel_endpoint is used in the IPsec hook under test below to
	 * find the associated NodeID for an egress packet
	 */
	ipcache_v4_add_entry(DST_IP, 0, 0xAC, DST_IP, 0);

	ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP));
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
