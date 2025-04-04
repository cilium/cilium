/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

#include "common.h"
#include "pktgen.h"

#define POD_IP			v4_pod_one
#define POD_PORT		__bpf_htons(NAT_MIN_EGRESS)
#define POD_IDENTITY		0x1234
#define POD_IFINDEX		10
#define POD_ENDPOINT_ID		100

#define NODE_IP			v4_node_one
#define NODE_PORT		__bpf_htons(NAT_MIN_EGRESS+1)
#define NODE_SPI		2

#define REMOTE_POD_IP		v4_pod_two
#define REMOTE_POD_PORT		__bpf_htons(2000)
#define REMOTE_POD_IDENTITY	0x1235
#define REMOTE_NODE_IP		v4_node_two
#define REMOTE_NODE_PORT	__bpf_htons(2001)
#define REMOTE_NODE_NODE_ID	123
#define REMOTE_NODE_SPI		3

/* A node with .skip_tunnel */
#define REMOTE_NODE2_IP		v4_node_three
#define REMOTE_NODE2_PORT	__bpf_htons(2001)
#define REMOTE_NODE2_NODE_ID	124
#define REMOTE_NODE2_SPI	3


#define EXTERNAL_IP		v4_ext_one
#define EXTERNAL_PORT		__bpf_htons(3000)

#ifdef ENABLE_MASQUERADE_IPV4
 #define IPV4_SNAT_EXCLUSION_DST_CIDR		v4_pod_cidr
 #define IPV4_SNAT_EXCLUSION_DST_CIDR_LEN	v4_pod_cidr_len
#endif

static volatile const __u8 *node_mac = mac_one;
static volatile const __u8 *remote_node_mac = mac_two;
static volatile const __u8 *external_mac = mac_three;

struct mock_redirect {
	int redirect_ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_redirect));
	__uint(max_entries, 1);
} mock_redirect_map __section_maps_btf;

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	__u32 key = 0;
	struct mock_redirect *settings = map_lookup_elem(&mock_redirect_map, &key);

	if (settings)
		settings->redirect_ifindex = ifindex;

	return CTX_ACT_REDIRECT;
}

#include "bpf_host.c"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/node.h"

#define TO_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/***********************************************************************/

SETUP("tc", "netdev_0000_init")
int netdev_0000_init_setup(__maybe_unused struct __ctx_buff *ctx)
{
	/* TODO validate these */
	endpoint_v4_add_entry(POD_IP, POD_IFINDEX, POD_ENDPOINT_ID, 0,
			      POD_IDENTITY, 0, NULL, (__u8 *)node_mac);
	endpoint_v4_add_entry(NODE_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, (__u8 *)node_mac);

	/* TODO validate these */
	ipcache_v4_add_entry(POD_IP, 0, POD_IDENTITY, 0, 0);
	ipcache_v4_add_entry(NODE_IP, 0, HOST_ID, 0, 0);

	ipcache_v4_add_entry(REMOTE_POD_IP, 0, REMOTE_POD_IDENTITY,
			     REMOTE_NODE_IP, REMOTE_NODE_SPI);
#if defined(ENABLE_WIREGUARD) && defined(ENABLE_NODE_ENCRYPTION)
	ipcache_v4_add_entry(REMOTE_NODE_IP, 0, REMOTE_NODE_ID,
			     0, REMOTE_NODE_SPI);
	ipcache_v4_add_entry_with_flags(REMOTE_NODE2_IP, 0, REMOTE_NODE_ID,
					0, REMOTE_NODE2_SPI, true);
#else
	ipcache_v4_add_entry(REMOTE_NODE_IP, 0, REMOTE_NODE_ID,
			     0, 0);
	ipcache_v4_add_entry_with_flags(REMOTE_NODE2_IP, 0, REMOTE_NODE_ID,
					0, 0, true);
#endif

	ipcache_v4_add_world_entry();

#ifdef ENABLE_IPSEC
	struct encrypt_config encrypt_value = { .encrypt_key = NODE_SPI };
	__u32 encrypt_key = 0;

	map_update_elem(&cilium_encrypt_state, &encrypt_key, &encrypt_value, BPF_ANY);

	node_v4_add_entry(REMOTE_NODE_IP, REMOTE_NODE_NODE_ID, REMOTE_NODE_SPI);
	node_v4_add_entry(REMOTE_NODE2_IP, REMOTE_NODE2_NODE_ID, REMOTE_NODE_SPI);
#endif

	return 0;
}

CHECK("tc", "netdev_0000_init")
int netdev_0000_init_check(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();
	/* TODO anything? */
	test_finish();
}

#ifdef ENABLE_MASQUERADE_IPV4
# include "connectivity_netdev/pod_bpf_masq.h"
#else
  /* TODO the iptables masq mode doesn't make sense yet */
# include "connectivity_netdev/pod_iptables_masq.h"
#endif

#include "connectivity_netdev/host.h"
#include "connectivity_netdev/proxy.h"

#ifdef ENABLE_IPSEC
# include "connectivity_netdev/esp.h"
#endif

#ifdef ENABLE_WIREGUARD
# include "connectivity_netdev/wireguard.h"
#endif

#ifdef HAVE_ENCAP
# if TUNNEL_PROTOCOL == TUNNEL_PROTOCOL_VXLAN
#  include "connectivity_netdev/vxlan.h"
# else
#  include "connectivity_netdev/geneve.h"
# endif
#endif

#include "connectivity_netdev/lb.h"
