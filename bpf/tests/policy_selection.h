/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Policy selection scenarios shared by policy_selection_legacy.c and
 * policy_selection_shared.c.
 *
 * The same scenarios are run against the per-endpoint policy map (enable_shared_policy=false)
 * and against cilium_policy_shared (enable_shared_policy=true), and must produce identical
 * results: the shared policy map only changes where policy entries are stored, not how the
 * entry for a packet is selected.
 *
 * Each scenario checks the verdict, the selected entry (by cookie), the match type and proxy
 * port reported to monitor/Hubble, and the policy stats key that gets incremented.
 *
 * The includer defines USE_SHARED (0 or 1).
 */

#define EP_ID		1
#define RS_ID		11
#define POD_ID		12345		/* global scope, cluster 0, aggregates to AGGREGATE_CLUSTER_ID */
#define POD_ID_2	12346
#define CIDR_ID		0x01000001	/* local CIDR scope, aggregates to AGGREGATE_WORLD_ID */
#define RNODE_ID	0x02000001	/* remote-node scope, aggregates to AGGREGATE_REMOTE_NODE_ID */
#define RESERVED_ID	2		/* reserved world, < 100, aggregates to 0 */

#define PREC_LO		0x00ff0000
#define PREC_HI		0x00ff0100
#define NO_MATCH_TYPE	0xff
#define EGRESS		1
#define INGRESS		0

/* ---- map helpers (legacy or shared) --------------------------------------------------- */

static __always_inline void
put(__u8 egress, __u32 identity, __u8 proto, __be16 port, __u8 port_range, bool deny,
    __u32 precedence, __be16 proxy_port, __u32 cookie)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, port_range);
	struct policy_entry value = {
		.proxy_port = proxy_port,
		.deny = deny,
		.lpm_prefix_length = LPM_FULL_PREFIX_BITS - wildcard_bits,
		.precedence = precedence,
		.cookie = cookie,
	};
#if USE_SHARED
	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = SHARED_POLICY_FULL_PREFIX - wildcard_bits },
		.rule_set_id = RS_ID,
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_update_elem(&cilium_policy_shared, &key, &value, BPF_ANY);
#else
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX - wildcard_bits, {} },
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_update_elem(&cilium_policy, &key, &value, BPF_ANY);
#endif
}

static __always_inline void
del(__u8 egress, __u32 identity, __u8 proto, __be16 port, __u8 port_range)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, port_range);
#if USE_SHARED
	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = SHARED_POLICY_FULL_PREFIX - wildcard_bits },
		.rule_set_id = RS_ID,
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_delete_elem(&cilium_policy_shared, &key);
#else
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX - wildcard_bits, {} },
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_delete_elem(&cilium_policy, &key);
#endif
}

static __always_inline void begin(void)
{
#if USE_SHARED
	__u32 ep = EP_ID, rs = RS_ID;

	map_update_elem(&cilium_policy_overlay, &ep, &rs, BPF_ANY);
#endif
}

/* Checks that exactly this stats key was incremented, then removes it. */
static __always_inline bool
stats_hit(__u32 sec_label, __u8 egress, __u8 proto, __be16 dport, __u8 prefix_len)
{
	struct policy_stats_key k = {
		.endpoint_id = EP_ID,
		.prefix_len = prefix_len,
		.sec_label = sec_label,
		.egress = egress,
		.protocol = proto,
		.dport = dport,
	};
	struct policy_stats_value *v = map_lookup_elem(&cilium_policystats, &k);
	bool ok = v && v->packets >= 1;

	map_delete_elem(&cilium_policystats, &k);
	return ok;
}

static __always_inline bool
stats_absent(__u32 sec_label, __u8 egress, __u8 proto, __be16 dport, __u8 prefix_len)
{
	struct policy_stats_key k = {
		.endpoint_id = EP_ID,
		.prefix_len = prefix_len,
		.sec_label = sec_label,
		.egress = egress,
		.protocol = proto,
		.dport = dport,
	};

	return !map_lookup_elem(&cilium_policystats, &k);
}

struct res {
	int ret;
	__u32 cookie;
	__u16 proxy_port;
	__u8 match_type;
};

static __always_inline struct res
egress(struct __ctx_buff *ctx, __u32 dst_id, __u8 proto, __be16 dport)
{
	struct res r = { .match_type = NO_MATCH_TYPE };
	__u8 audited = 0;

	r.ret = policy_can_egress(ctx, EP_ID /* src, local */, dst_id, 0, dport, proto, 0,
				  &r.match_type, &audited, &r.proxy_port, &r.cookie);
	return r;
}

static __always_inline struct res
ingress(struct __ctx_buff *ctx, __u32 src_id, __u8 proto, __be16 dport, bool frag)
{
	struct res r = { .match_type = NO_MATCH_TYPE };
	__u8 audited = 0;

	r.ret = policy_can_ingress(ctx, src_id, EP_ID /* dst, local */, 0, dport, proto, 0,
				   frag, &r.match_type, &audited, &r.proxy_port, &r.cookie);
	return r;
}

#define P80	__bpf_htons(80)

/* ---- scenarios -------------------------------------------------------------------------- */

CHECK("tc", "d01_no_entry_drops")
int d01(struct __ctx_buff *ctx)
{
	test_init();
	TEST("no entry: DROP_POLICY", {
		struct res r;

		begin();
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		assert(r.ret == DROP_POLICY);
		assert(r.match_type == NO_MATCH_TYPE);
	});
	test_finish();
}

CHECK("tc", "d02_l3_only")
int d02(struct __ctx_buff *ctx)
{
	test_init();
	TEST("specific L3-only allow", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, 0, 0, 0, false, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, 0, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 2);
		assert(r.match_type == POLICY_MATCH_L3_ONLY);
		assert(stats_hit(POD_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "d03_l3_proto")
int d03(struct __ctx_buff *ctx)
{
	test_init();
	TEST("specific L3 + proto allow", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, 0, 0, false, PREC_LO, 0, 3);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 3);
		assert(r.match_type == POLICY_MATCH_L3_PROTO);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, 0, 8));
	});
	test_finish();
}

CHECK("tc", "d04_l3_l4_proxy")
int d04(struct __ctx_buff *ctx)
{
	test_init();
	TEST("specific L3/L4 allow with proxy redirect", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO,
		    __bpf_htons(15001), 4);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 4);
		assert(r.proxy_port == __bpf_htons(15001));
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d05_agg_l4")
int d05(struct __ctx_buff *ctx)
{
	test_init();
	TEST("aggregate (cluster) L4 allow", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 5);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 5);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_absent(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d06_agg_proto")
int d06(struct __ctx_buff *ctx)
{
	test_init();
	TEST("aggregate proto-only allow", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, 0, 0, false, PREC_LO, 0, 6);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 6);
		assert(r.match_type == POLICY_MATCH_PROTO_ONLY);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, IPPROTO_TCP, 0, 8));
	});
	test_finish();
}

CHECK("tc", "d07_agg_all")
int d07(struct __ctx_buff *ctx)
{
	test_init();
	TEST("aggregate allow-all", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0, 0, false, PREC_LO, 0, 7);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 7);
		assert(r.match_type == POLICY_MATCH_ALL);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "d08_id0_fallback")
int d08(struct __ctx_buff *ctx)
{
	test_init();
	TEST("ID-0 fallback when neither specific nor aggregate exists", {
		struct res r;

		begin();
		put(EGRESS, 0, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 8);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, 0, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 8);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_hit(0, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d09_issue48945_agg_longer")
int d09(struct __ctx_buff *ctx)
{
	test_init();
	TEST("specific TCP/ANY + aggregate TCP/80: aggregate wins", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, 0, 0, false, PREC_LO, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, 0, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 2);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_absent(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d10_specific_longer")
int d10(struct __ctx_buff *ctx)
{
	test_init();
	TEST("specific TCP/80 + aggregate TCP/ANY: specific wins", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, 0, 0, false, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 1);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d11_equal_prefix")
int d11(struct __ctx_buff *ctx)
{
	test_init();
	TEST("equal prefix, equal precedence: specific wins", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 1);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d12_agg_higher_precedence")
int d12(struct __ctx_buff *ctx)
{
	test_init();
	TEST("aggregate with higher precedence wins over more specific entry", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0, 0, false, PREC_HI,
		    __bpf_htons(15002), 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 2);
		assert(r.proxy_port == __bpf_htons(15002));
		assert(r.match_type == POLICY_MATCH_ALL);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "d13_max_deny_short_circuit")
int d13(struct __ctx_buff *ctx)
{
	test_init();
	TEST("max-precedence specific deny wins without aggregate lookup", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, 0, 0, 0, true, MAX_PRECEDENCE, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0, true, MAX_PRECEDENCE,
		    0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, 0, 0, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == DROP_POLICY_DENY);
		assert(r.cookie == 1);
		assert(r.match_type == POLICY_MATCH_L3_ONLY);
		assert(stats_hit(POD_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "d14_same_prec_denies")
int d14(struct __ctx_buff *ctx)
{
	test_init();
	TEST("same-precedence denies: aggregate with longer prefix wins", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, 0, 0, 0, true, PREC_LO, 0, 1);
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0, true, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, 0, 0, 0);
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == DROP_POLICY_DENY);
		assert(r.cookie == 2);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d15_no_id0_fallback_with_specific")
int d15(struct __ctx_buff *ctx)
{
	test_init();
	TEST("no ID-0 fallback when specific matched and aggregate missed", {
		struct res r;

		begin();
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 1);
		put(EGRESS, 0, IPPROTO_TCP, P80, 0, true, PREC_HI, 0, 3);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		del(EGRESS, 0, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 1);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d16_port_range")
int d16(struct __ctx_buff *ctx)
{
	test_init();
	TEST("aggregate port range 8080-8095, flow on 8090", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, __bpf_htons(8080), 4, false,
		    PREC_LO, 0, 16);
		r = egress(ctx, POD_ID, IPPROTO_TCP, __bpf_htons(8090));
		del(EGRESS, AGGREGATE_CLUSTER_ID, IPPROTO_TCP, __bpf_htons(8080), 4);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 16);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, IPPROTO_TCP,
				 __bpf_htons(8080), 20));
	});
	test_finish();
}

CHECK("tc", "d17_cidr_world_agg")
int d17(struct __ctx_buff *ctx)
{
	test_init();
	TEST("CIDR identity matched by world aggregate", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_WORLD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 17);
		r = egress(ctx, CIDR_ID, IPPROTO_TCP, P80);
		del(EGRESS, AGGREGATE_WORLD_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 17);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_hit(AGGREGATE_WORLD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d18_remote_node_agg")
int d18(struct __ctx_buff *ctx)
{
	test_init();
	TEST("remote-node identity matched by remote-node aggregate", {
		struct res r;

		begin();
		put(EGRESS, AGGREGATE_REMOTE_NODE_ID, 0, 0, 0, false, PREC_LO, 0, 18);
		r = egress(ctx, RNODE_ID, IPPROTO_UDP, __bpf_htons(53));
		del(EGRESS, AGGREGATE_REMOTE_NODE_ID, 0, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 18);
		assert(r.match_type == POLICY_MATCH_ALL);
		assert(stats_hit(AGGREGATE_REMOTE_NODE_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "d19_reserved_id_agg0")
int d19(struct __ctx_buff *ctx)
{
	test_init();
	TEST("reserved identity (<100) aggregates to ID 0", {
		struct res r;

		begin();
		put(EGRESS, 0, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 19);
		r = egress(ctx, RESERVED_ID, IPPROTO_TCP, P80);
		del(EGRESS, 0, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 19);
		assert(r.match_type == POLICY_MATCH_L4_ONLY);
		assert(stats_hit(0, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d20_ingress_l3_l4")
int d20(struct __ctx_buff *ctx)
{
	test_init();
	TEST("ingress specific L3/L4 allow", {
		struct res r;

		begin();
		put(INGRESS, POD_ID_2, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 20);
		r = ingress(ctx, POD_ID_2, IPPROTO_TCP, P80, false);
		del(INGRESS, POD_ID_2, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 20);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID_2, INGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "d21_direction_isolation")
int d21(struct __ctx_buff *ctx)
{
	test_init();
	TEST("egress entry does not match ingress traffic", {
		struct res r;

		begin();
		put(EGRESS, POD_ID_2, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 21);
		r = ingress(ctx, POD_ID_2, IPPROTO_TCP, P80, false);
		del(EGRESS, POD_ID_2, IPPROTO_TCP, P80, 0);
		assert(r.ret == DROP_POLICY);
	});
	test_finish();
}

CHECK("tc", "d22_untracked_fragment")
int d22(struct __ctx_buff *ctx)
{
	test_init();
	TEST("untracked fragment without match: DROP_FRAG_NOSUPPORT", {
		struct res r;

		begin();
		r = ingress(ctx, POD_ID_2, IPPROTO_UDP, 0, true);
		assert(r.ret == DROP_FRAG_NOSUPPORT);
	});
	test_finish();
}

CHECK("tc", "d23_untracked_fragment_l3")
int d23(struct __ctx_buff *ctx)
{
	test_init();
	TEST("untracked fragment matched by L3-only entry", {
		struct res r;

		begin();
		put(INGRESS, POD_ID_2, 0, 0, 0, false, PREC_LO, 0, 23);
		r = ingress(ctx, POD_ID_2, IPPROTO_UDP, 0, true);
		del(INGRESS, POD_ID_2, 0, 0, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 23);
		assert(r.match_type == POLICY_MATCH_L3_ONLY);
		assert(stats_hit(POD_ID_2, INGRESS, 0, 0, 0));
	});
	test_finish();
}

#if USE_SHARED
/* ---- shared policy map: endpoints without an overlay entry ----------------------------- */

static __always_inline void no_overlay(void)
{
	__u32 ep = EP_ID;

	map_delete_elem(&cilium_policy_overlay, &ep);
}

static __always_inline void
put_legacy(__u8 egress, __u32 identity, __u8 proto, __be16 port, bool deny, __u32 cookie)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, 0);
	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = LPM_FULL_PREFIX_BITS - wildcard_bits,
		.precedence = PREC_LO,
		.cookie = cookie,
	};
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX - wildcard_bits, {} },
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_update_elem(&cilium_policy, &key, &value, BPF_ANY);
}

static __always_inline void
del_legacy(__u8 egress, __u32 identity, __u8 proto, __be16 port)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, 0);
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX - wildcard_bits, {} },
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};

	map_delete_elem(&cilium_policy, &key);
}

CHECK("tc", "s01_no_overlay_empty_map_drops")
int s01(struct __ctx_buff *ctx)
{
	test_init();
	TEST("no overlay entry and empty per-endpoint map: DROP_POLICY", {
		struct res r;

		no_overlay();
		/* An entry in the shared map must not be used without an overlay entry. */
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 1);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == DROP_POLICY);
		assert(r.match_type == NO_MATCH_TYPE);
	});
	test_finish();
}

CHECK("tc", "s02_no_overlay_uses_endpoint_map")
int s02(struct __ctx_buff *ctx)
{
	test_init();
	TEST("no overlay entry: per-endpoint map entry is selected", {
		struct res r;

		no_overlay();
		put_legacy(EGRESS, POD_ID, IPPROTO_TCP, P80, false, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del_legacy(EGRESS, POD_ID, IPPROTO_TCP, P80);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 2);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}

CHECK("tc", "s03_no_overlay_endpoint_map_deny")
int s03(struct __ctx_buff *ctx)
{
	test_init();
	TEST("no overlay entry: per-endpoint map deny is enforced", {
		struct res r;

		no_overlay();
		put_legacy(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0, true, 3);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del_legacy(EGRESS, AGGREGATE_CLUSTER_ID, 0, 0);
		assert(r.ret == DROP_POLICY_DENY);
		assert(r.cookie == 3);
		assert(r.match_type == POLICY_MATCH_ALL);
		assert(stats_hit(AGGREGATE_CLUSTER_ID, EGRESS, 0, 0, 0));
	});
	test_finish();
}

CHECK("tc", "s04_overlay_ignores_endpoint_map")
int s04(struct __ctx_buff *ctx)
{
	test_init();
	TEST("overlay entry present: per-endpoint map entries are not used", {
		struct res r;

		begin();
		put_legacy(EGRESS, POD_ID, IPPROTO_TCP, P80, false, 4);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del_legacy(EGRESS, POD_ID, IPPROTO_TCP, P80);
		assert(r.ret == DROP_POLICY);
		assert(r.match_type == NO_MATCH_TYPE);
	});
	test_finish();
}
#endif /* USE_SHARED */

#if !USE_SHARED && defined(SHARED_POLICY_FULL_PREFIX)
/* ---- shared policy map disabled: shared policy map contents are ignored ----------------- */

static __always_inline void
put_shared(__u8 egress, __u32 identity, __u8 proto, __be16 port, bool deny, __u32 cookie)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, 0);
	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = LPM_FULL_PREFIX_BITS - wildcard_bits,
		.precedence = PREC_LO,
		.cookie = cookie,
	};
	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = SHARED_POLICY_FULL_PREFIX - wildcard_bits },
		.rule_set_id = RS_ID,
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};
	__u32 ep = EP_ID, rs = RS_ID;

	map_update_elem(&cilium_policy_shared, &key, &value, BPF_ANY);
	map_update_elem(&cilium_policy_overlay, &ep, &rs, BPF_ANY);
}

static __always_inline void
del_shared(__u8 egress, __u32 identity, __u8 proto, __be16 port)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, 0);
	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = SHARED_POLICY_FULL_PREFIX - wildcard_bits },
		.rule_set_id = RS_ID,
		.sec_label = identity,
		.egress = egress,
		.protocol = proto,
		.dport = port,
	};
	__u32 ep = EP_ID;

	map_delete_elem(&cilium_policy_shared, &key);
	map_delete_elem(&cilium_policy_overlay, &ep);
}

CHECK("tc", "l01_disabled_ignores_shared_allow")
int l01(struct __ctx_buff *ctx)
{
	test_init();
	TEST("disabled: shared allow + overlay entry, empty per-endpoint map: DROP_POLICY", {
		struct res r;

		put_shared(EGRESS, POD_ID, IPPROTO_TCP, P80, false, 1);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del_shared(EGRESS, POD_ID, IPPROTO_TCP, P80);
		assert(r.ret == DROP_POLICY);
		assert(r.match_type == NO_MATCH_TYPE);
	});
	test_finish();
}

CHECK("tc", "l02_disabled_ignores_shared_deny")
int l02(struct __ctx_buff *ctx)
{
	test_init();
	TEST("disabled: shared deny is ignored, per-endpoint allow is selected", {
		struct res r;

		put_shared(EGRESS, POD_ID, 0, 0, true, 1);
		put(EGRESS, POD_ID, IPPROTO_TCP, P80, 0, false, PREC_LO, 0, 2);
		r = egress(ctx, POD_ID, IPPROTO_TCP, P80);
		del_shared(EGRESS, POD_ID, 0, 0);
		del(EGRESS, POD_ID, IPPROTO_TCP, P80, 0);
		assert(r.ret == CTX_ACT_OK);
		assert(r.cookie == 2);
		assert(r.match_type == POLICY_MATCH_L3_L4);
		assert(stats_hit(POD_ID, EGRESS, IPPROTO_TCP, P80, 24));
	});
	test_finish();
}
#endif /* !USE_SHARED && SHARED_POLICY_FULL_PREFIX */
