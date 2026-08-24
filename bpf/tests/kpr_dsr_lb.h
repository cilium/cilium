/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ATTACHMENT_XDP
# include <bpf/ctx/xdp.h>
#else
# include <bpf/ctx/skb.h>
#endif

#include "common.h"

#include "pktgen.h"
#include "scapy.h"

#define ENABLE_DSR_ICMP_ERRORS		1

#define fib_lookup mock_fib_lookup
long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = 22;

	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_one, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_two, ETH_ALEN);

	return 0;
}

bool tunnel_key_set;
bool tunnel_opt_set;

#ifdef ATTACHMENT_XDP
# include "lib/bpf_xdp.h"
# define netdev_receive_packet  xdp_receive_packet
#else
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_tunnel_key));
	__uint(max_entries, 1);
} tunnel_key_map __section_maps_btf;

# define skb_set_tunnel_key mock_skb_set_tunnel_key
int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const struct bpf_tunnel_key *from,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	__u32 map_key = 0;
	struct bpf_tunnel_key *mock_key = map_lookup_elem(&tunnel_key_map, &map_key);

	if (mock_key) {
		memcpy(mock_key, from, sizeof(*from));
		tunnel_key_set = true;
	}

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct geneve_dsr_opt6));
	__uint(max_entries, 1);
} tunnel_opt_map __section_maps_btf;

# define skb_set_tunnel_opt mock_skb_set_tunnel_opt
int mock_skb_set_tunnel_opt(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const void *opt,
			    __maybe_unused __u32 opt_len)
{
	__u32 map_key = 0;
	void *data = map_lookup_elem(&tunnel_opt_map, &map_key);

	if (!data)
		return -1;

	switch (opt_len) {
	case sizeof(struct geneve_dsr_opt4):
		memcpy(data, opt, sizeof(struct geneve_dsr_opt4));
		tunnel_opt_set = true;
		return 0;
	case sizeof(struct geneve_dsr_opt6):
		memcpy(data, opt, sizeof(struct geneve_dsr_opt6));
		tunnel_opt_set = true;
		return 0;
	default:
		return -1;
	}
}

# include "lib/bpf_host.h"
#endif /* ATTACHMENT_XDP */

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
#endif

ASSIGN_CONFIG(__u32, hash_init4_seed, 0xcafe)
ASSIGN_CONFIG(__u32, hash_init6_seed, 0xeb9f)

ASSIGN_CONFIG(__u16, device_mtu, 200);

ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_one })

#include "lib/ipcache.h"
#include "lib/lb.h"

const __u8 kpr_v4_dsr_lb1_syn[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn)
};

const __u8 kpr_v4_dsr_lb1_syn_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn_post_option)
};

const __u8 kpr_v4_dsr_lb1_syn_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn_post_option_xdp)
};

const __u8 kpr_v4_dsr_lb1_syn_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn_post_geneve)
};

const __u8 kpr_v4_dsr_lb1_syn_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_syn_post_geneve_xdp)
};

const __u8 kpr_v4_dsr_lb1_synack[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack)
};

const __u8 kpr_v4_dsr_lb1_synack_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack_post_option)
};

const __u8 kpr_v4_dsr_lb1_synack_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack_post_option_xdp)
};

const __u8 kpr_v4_dsr_lb1_synack_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack_post_geneve)
};

const __u8 kpr_v4_dsr_lb1_synack_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb1_synack_post_geneve_xdp)
};

const __u8 kpr_v4_dsr_lb2_data[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb2_data)
};

const __u8 kpr_v4_dsr_lb2_data_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb2_data_post_option)
};

const __u8 kpr_v4_dsr_lb2_data_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb2_data_post_option_xdp)
};

const __u8 kpr_v4_dsr_lb2_data_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb2_data_post_geneve)
};

const __u8 kpr_v4_dsr_lb2_data_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v4_dsr_lb2_data_post_geneve_xdp)
};

const __u8 kpr_v4_dsr_lb3_mtu[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu)
};

const __u8 kpr_v4_dsr_lb3_mtu_post_option[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu_post_option)
};

const __u8 kpr_v4_dsr_lb3_mtu_post_geneve[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu_post_geneve)
};

const __u8 kpr_v4_dsr_lb3_mtu2[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu2)
};

const __u8 kpr_v4_dsr_lb3_mtu2_post_option[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu2_post_option)
};

const __u8 kpr_v4_dsr_lb3_mtu2_post_option_xdp[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu2_post_option_xdp)
};

const __u8 kpr_v4_dsr_lb3_mtu2_post_geneve[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu2_post_geneve)
};

const __u8 kpr_v4_dsr_lb3_mtu2_post_geneve_xdp[] = {
       SCAPY_BUF_BYTES(kpr_v4_dsr_lb3_mtu2_post_geneve_xdp)
};

const __u8 kpr_v6_dsr_lb1_syn[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn)
};

const __u8 kpr_v6_dsr_lb1_syn_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn_post_option)
};

const __u8 kpr_v6_dsr_lb1_syn_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn_post_option_xdp)
};

const __u8 kpr_v6_dsr_lb1_syn_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn_post_geneve)
};

const __u8 kpr_v6_dsr_lb1_syn_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_syn_post_geneve_xdp)
};

const __u8 kpr_v6_dsr_lb1_synack[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack)
};

const __u8 kpr_v6_dsr_lb1_synack_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack_post_option)
};

const __u8 kpr_v6_dsr_lb1_synack_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack_post_option_xdp)
};

const __u8 kpr_v6_dsr_lb1_synack_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack_post_geneve)
};

const __u8 kpr_v6_dsr_lb1_synack_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb1_synack_post_geneve_xdp)
};

const __u8 kpr_v6_dsr_lb2_data[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb2_data)
};

const __u8 kpr_v6_dsr_lb2_data_post_option[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb2_data_post_option)
};

const __u8 kpr_v6_dsr_lb2_data_post_option_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb2_data_post_option_xdp)
};

const __u8 kpr_v6_dsr_lb2_data_post_geneve[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb2_data_post_geneve)
};

const __u8 kpr_v6_dsr_lb2_data_post_geneve_xdp[] = {
	SCAPY_BUF_BYTES(kpr_v6_dsr_lb2_data_post_geneve_xdp)
};

const __u8 kpr_v6_dsr_lb3_mtu[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu)
};

const __u8 kpr_v6_dsr_lb3_mtu_post_option[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu_post_option)
};

const __u8 kpr_v6_dsr_lb3_mtu_post_geneve[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu_post_geneve)
};

const __u8 kpr_v6_dsr_lb3_mtu2[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu2)
};

const __u8 kpr_v6_dsr_lb3_mtu2_post_option[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu2_post_option)
};

const __u8 kpr_v6_dsr_lb3_mtu2_post_option_xdp[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu2_post_option_xdp)
};

const __u8 kpr_v6_dsr_lb3_mtu2_post_geneve[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu2_post_geneve)
};

const __u8 kpr_v6_dsr_lb3_mtu2_post_geneve_xdp[] = {
       SCAPY_BUF_BYTES(kpr_v6_dsr_lb3_mtu2_post_geneve_xdp)
};

#ifdef ENABLE_IPV4
/* Client accesses a DSR service with remote backend.
 * We expect the SYN to carry DSR-info, but the SYN-ACK to be forwarded
 * without DSR-info.
 */
PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb1_syn")
int kpr_v4_dsr_lb1_syn_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_lb1_syn,
			sizeof(kpr_v4_dsr_lb1_syn));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb1_syn")
int kpr_v4_dsr_lb1_syn_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(v4_pod_one, 0, 112233, v4_node_two, 0);

	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb1_syn")
int kpr_v4_dsr_lb1_syn_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_syn_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_syn_post_geneve_xdp,
			   sizeof(kpr_v4_dsr_lb1_syn_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_syn_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_syn_post_geneve,
			   sizeof(kpr_v4_dsr_lb1_syn_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt4 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV4_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (dsr_opt->addr != v4_svc_one)
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_one)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_syn_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_syn_post_option_xdp,
			   sizeof(kpr_v4_dsr_lb1_syn_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_syn_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_syn_post_option,
			   sizeof(kpr_v4_dsr_lb1_syn_post_option));
# endif
#endif

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_svc_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_svc_one;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb1_synack")
int kpr_v4_dsr_lb1_synack_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_lb1_synack,
			sizeof(kpr_v4_dsr_lb1_synack));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb1_synack")
int kpr_v4_dsr_lb1_synack_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb1_synack")
int kpr_v4_dsr_lb1_synack_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
 # ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_synack_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_synack_post_geneve_xdp,
			   sizeof(kpr_v4_dsr_lb1_synack_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_synack_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_synack_post_geneve,
			   sizeof(kpr_v4_dsr_lb1_synack_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("expected DSR opt");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_synack_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_synack_post_option_xdp,
			   sizeof(kpr_v4_dsr_lb1_synack_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb1_synack_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb1_synack_post_option,
			   sizeof(kpr_v4_dsr_lb1_synack_post_option));
# endif
#endif

	test_finish();
}

/* Client's TCP connection is interrupted, and switches to a different LB node.
 * We expect all subsequent data packets to carry DSR-info.
 */
PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb2_data")
int kpr_v4_dsr_lb2_data_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_lb2_data,
			sizeof(kpr_v4_dsr_lb2_data));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb2_data")
int kpr_v4_dsr_lb2_data_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;

	lb_v4_add_service(v4_svc_one, tcp_svc_two, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_two, 1, 124,
			  v4_pod_one, tcp_dst_two, IPPROTO_TCP, 0);

	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb2_data")
int kpr_v4_dsr_lb2_data_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb2_data_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb2_data_post_geneve_xdp,
			   sizeof(kpr_v4_dsr_lb2_data_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb2_data_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb2_data_post_geneve,
			   sizeof(kpr_v4_dsr_lb2_data_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt4 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV4_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (dsr_opt->addr != v4_svc_one)
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_two)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb2_data_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb2_data_post_option_xdp,
			   sizeof(kpr_v4_dsr_lb2_data_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb2_data_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb2_data_post_option,
			   sizeof(kpr_v4_dsr_lb2_data_post_option));
# endif
#endif

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_svc_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_svc_two;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb2_data2")
int kpr_v4_dsr_lb2_data2_pktgen(struct __ctx_buff *ctx)
{
	return kpr_v4_dsr_lb2_data_pktgen(ctx);
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb2_data2")
int kpr_v4_dsr_lb2_data2_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb2_data2")
int kpr_v4_dsr_lb2_data2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return kpr_v4_dsr_lb2_data_check(ctx);
}

/* Send an ICMP error msg when the DSR-info doesn't fit into the request. */
PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb3_mtu")
int kpr_v4_dsr_lb3_mtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_lb3_mtu,
			sizeof(kpr_v4_dsr_lb3_mtu));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb3_mtu")
int kpr_v4_dsr_lb3_mtu_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 3;

	lb_v4_add_service(v4_svc_one, tcp_svc_three, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_three, 1, 124,
			  v4_pod_one, tcp_dst_three, IPPROTO_TCP, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb3_mtu")
int kpr_v4_dsr_lb3_mtu_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_TX);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu_post_geneve,
			   sizeof(kpr_v4_dsr_lb3_mtu_post_geneve));
#else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu_post_option,
			   sizeof(kpr_v4_dsr_lb3_mtu_post_option));
#endif

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_svc_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_svc_three;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");
	if (!ct_entry->need_dsr_info)
		test_fatal("CT entry doesn't have need_dsr_info flag");

	test_finish();
}

/* First successful packet after ICMP error msg has DSR-info inserted. */
PKTGEN(PROG_TYPE, "kpr_v4_dsr_lb3_mtu2")
int kpr_v4_dsr_lb3_mtu2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v4_dsr_lb3_mtu2,
			sizeof(kpr_v4_dsr_lb3_mtu2));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v4_dsr_lb3_mtu2")
int kpr_v4_dsr_lb3_mtu2_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v4_dsr_lb3_mtu2")
int kpr_v4_dsr_lb3_mtu2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu2_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu2_post_geneve_xdp,
			   sizeof(kpr_v4_dsr_lb3_mtu2_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu2_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu2_post_geneve,
			   sizeof(kpr_v4_dsr_lb3_mtu2_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt4 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV4_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (dsr_opt->addr != v4_svc_one)
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_three)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu2_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu2_post_option_xdp,
			   sizeof(kpr_v4_dsr_lb3_mtu2_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v4_dsr_lb3_mtu2_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v4_dsr_lb3_mtu2_post_option,
			   sizeof(kpr_v4_dsr_lb3_mtu2_post_option));
# endif
#endif

	struct ipv4_ct_tuple tuple;
	struct ct_entry *ct_entry;

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.daddr = v4_svc_one;
	tuple.saddr = v4_ext_one;
	tuple.sport = tcp_svc_three;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");
	if (!ct_entry->need_dsr_info)
		test_fatal("CT entry lost the need_dsr_info flag");

	test_finish();
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb1_syn")
int kpr_v6_dsr_lb1_syn_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_lb1_syn,
			sizeof(kpr_v6_dsr_lb1_syn));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb1_syn")
int kpr_v6_dsr_lb1_syn_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;
	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr backend_ip = { v6_pod_one_addr };

	lb_v6_add_service(&frontend_ip, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, tcp_svc_one, 1, 124,
			  &backend_ip, tcp_dst_one, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, v4_node_two, 0);

	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb1_syn")
int kpr_v6_dsr_lb1_syn_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = { v6_svc_one_addr };
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_syn_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_syn_post_geneve_xdp,
			   sizeof(kpr_v6_dsr_lb1_syn_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_syn_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_syn_post_geneve,
			   sizeof(kpr_v6_dsr_lb1_syn_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt6 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV6_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (!ipv6_addr_equals((union v6addr *)&dsr_opt->addr, &frontend_ip))
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_one)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_syn_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_syn_post_option_xdp,
			   sizeof(kpr_v6_dsr_lb1_syn_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_syn_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_syn_post_option,
			   sizeof(kpr_v6_dsr_lb1_syn_post_option));
# endif
#endif

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &frontend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_svc_one;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb1_synack")
int kpr_v6_dsr_lb1_synack_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_lb1_synack,
			sizeof(kpr_v6_dsr_lb1_synack));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb1_synack")
int kpr_v6_dsr_lb1_synack_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb1_synack")
int kpr_v6_dsr_lb1_synack_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_synack_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_synack_post_geneve_xdp,
			   sizeof(kpr_v6_dsr_lb1_synack_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_synack_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_synack_post_geneve,
			   sizeof(kpr_v6_dsr_lb1_synack_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("expected DSR opt");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_synack_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_synack_post_option_xdp,
			   sizeof(kpr_v6_dsr_lb1_synack_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb1_synack_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb1_synack_post_option,
			   sizeof(kpr_v6_dsr_lb1_synack_post_option));
# endif
#endif

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb2_data")
int kpr_v6_dsr_lb2_data_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_lb2_data,
			sizeof(kpr_v6_dsr_lb2_data));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb2_data")
int kpr_v6_dsr_lb2_data_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 2;
	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr backend_ip = { v6_pod_one_addr };

	lb_v6_add_service(&frontend_ip, tcp_svc_two, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, tcp_svc_two, 1, 124,
			  &backend_ip, tcp_dst_two, IPPROTO_TCP, 0);

	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb2_data")
int kpr_v6_dsr_lb2_data_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = { v6_svc_one_addr };
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb2_data_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb2_data_post_geneve_xdp,
			   sizeof(kpr_v6_dsr_lb2_data_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb2_data_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb2_data_post_geneve,
			   sizeof(kpr_v6_dsr_lb2_data_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt6 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV6_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (!ipv6_addr_equals((union v6addr *)&dsr_opt->addr, &frontend_ip))
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_two)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb2_data_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb2_data_post_option_xdp,
			   sizeof(kpr_v6_dsr_lb2_data_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb2_data_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb2_data_post_option,
			   sizeof(kpr_v6_dsr_lb2_data_post_option));
# endif
#endif

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &frontend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_svc_two;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb2_data2")
int kpr_v6_dsr_lb2_data2_pktgen(struct __ctx_buff *ctx)
{
	return kpr_v6_dsr_lb2_data_pktgen(ctx);
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb2_data2")
int kpr_v6_dsr_lb2_data2_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb2_data2")
int kpr_v6_dsr_lb2_data2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	return kpr_v6_dsr_lb2_data_check(ctx);
}

PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb3_mtu")
int kpr_v6_dsr_lb3_mtu_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_lb3_mtu,
			sizeof(kpr_v6_dsr_lb3_mtu));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb3_mtu")
int kpr_v6_dsr_lb3_mtu_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 3;

	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr backend_ip = { v6_pod_one_addr };

	lb_v6_add_service(&frontend_ip, tcp_svc_three, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, tcp_svc_three, 1, 124,
			  &backend_ip, tcp_dst_three, IPPROTO_TCP, 0);

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb3_mtu")
int kpr_v6_dsr_lb3_mtu_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_TX);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu_post_geneve,
			   sizeof(kpr_v6_dsr_lb3_mtu_post_geneve));
#else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu_post_option,
			   sizeof(kpr_v6_dsr_lb3_mtu_post_option));
#endif

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr frontend_ip = { v6_svc_one_addr };
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &frontend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_svc_three;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");

	test_finish();
}

PKTGEN(PROG_TYPE, "kpr_v6_dsr_lb3_mtu2")
int kpr_v6_dsr_lb3_mtu2_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, kpr_v6_dsr_lb3_mtu2,
			sizeof(kpr_v6_dsr_lb3_mtu2));

	pktgen__finish(&builder);

	return 0;
}

SETUP(PROG_TYPE, "kpr_v6_dsr_lb3_mtu2")
int kpr_v6_dsr_lb3_mtu2_setup(struct __ctx_buff *ctx)
{
	tunnel_key_set = false;
	tunnel_opt_set = false;

	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "kpr_v6_dsr_lb3_mtu2")
int kpr_v6_dsr_lb3_mtu2_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = { v6_svc_one_addr };
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

#if DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu2_post_geneve_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu2_post_geneve_xdp,
			   sizeof(kpr_v6_dsr_lb3_mtu2_post_geneve_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu2_post_geneve",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu2_post_geneve,
			   sizeof(kpr_v6_dsr_lb3_mtu2_post_geneve));

	struct bpf_tunnel_key *tunnel_key;
	struct geneve_dsr_opt6 *dsr_opt;
	__u32 key = 0;

	if (!tunnel_key_set)
		test_fatal("no tunnel key set")
	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key");
	if (tunnel_key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != WORLD_ID)
		test_fatal("tunnel id is not correct");

	if (!tunnel_opt_set)
		test_fatal("no DSR opt set");
	dsr_opt = map_lookup_elem(&tunnel_opt_map, &key);
	if (!dsr_opt)
		test_fatal("no DSR opt");
	if (dsr_opt->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS))
		test_fatal("DSR opt class is not correct");
	if (dsr_opt->hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("DSR opt type is not correct");
	if (dsr_opt->hdr.length != DSR_IPV6_GENEVE_OPT_LEN)
		test_fatal("DSR opt length is not correct");
	if (!ipv6_addr_equals((union v6addr *)&dsr_opt->addr, &frontend_ip))
		test_fatal("DSR addr is not correct");
	if (dsr_opt->port != tcp_svc_three)
		test_fatal("DSR port is not correct");
# endif
#else
# ifdef ATTACHMENT_XDP
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu2_post_option_xdp",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu2_post_option_xdp,
			   sizeof(kpr_v6_dsr_lb3_mtu2_post_option_xdp));
# else
	ASSERT_CTX_BUF_OFF("kpr_v6_dsr_lb3_mtu2_post_option",
			   "Ether", ctx, sizeof(__u32),
			   kpr_v6_dsr_lb3_mtu2_post_option,
			   sizeof(kpr_v6_dsr_lb3_mtu2_post_option));
# endif
#endif

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	union v6addr client_ip = { v6_ext_node_one_addr };

	tuple.flags = TUPLE_F_SERVICE;
	tuple.nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&tuple.daddr, &frontend_ip);
	ipv6_addr_copy(&tuple.saddr, &client_ip);
	tuple.sport = tcp_svc_three;
	tuple.dport = tcp_src_one;

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR connection found");
	if (!ct_entry->need_dsr_info)
		test_fatal("CT entry lost the need_dsr_info flag");

	test_finish();
}
#endif /* ENABLE_IPV6 */
