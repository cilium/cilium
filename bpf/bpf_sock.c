/*
 *  Copyright (C) 2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#define SKIP_POLICY_MAP	1
#define SKIP_CALLS_MAP	1

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/lb.h"
#include "lib/eps.h"
#include "lib/metrics.h"

#define CONNECT_REJECT	0
#define CONNECT_PROCEED	1
#define SENDMSG_PROCEED	CONNECT_PROCEED
#define RECVMSG_PROCEED	CONNECT_PROCEED

static __always_inline __maybe_unused bool is_v4_loopback(__be32 daddr)
{
	/* Check for 127.0.0.0/8 range, RFC3330. */
	return (daddr & bpf_htonl(0x7f000000)) == bpf_htonl(0x7f000000);
}

static __always_inline __maybe_unused bool is_v6_loopback(union v6addr *daddr)
{
	/* Check for ::1/128, RFC4291. */
	union v6addr loopback = { .addr[15] = 1, };
	return ipv6_addrcmp(&loopback, daddr) == 0;
}

/* Hack due to missing narrow ctx access. */
static __always_inline __maybe_unused __be16
ctx_get_port(struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;
	return (__be16)dport;
}

static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

static __always_inline __maybe_unused
__u64 sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef HAVE_GET_SOCK_COOKIE
	/* prandom() breaks down on UDP, hence preference is on
	 * socket cookie as built-in selector. On older kernels,
	 * get_socket_cookie() provides a unique per netns cookie
	 * for the life-time of the socket. For newer kernels this
	 * is fixed to be a unique system _global_ cookie. Older
	 * kernels could have a cookie collision when two pods with
	 * different netns talk to same service backend, but that
	 * is fine since we always reverse translate to the same
	 * service IP/port pair. The only case that could happen
	 * for older kernels is that we have a cookie collision
	 * where one pod talks to the service IP/port and the
	 * other pod talks to that same specific backend IP/port
	 * directly _w/o_ going over service IP/port. Then the
	 * reverse sock addr is translated to the service IP/port.
	 * With a global socket cookie this collision cannot take
	 * place. There, only the even more unlikely case could
	 * happen where the same UDP socket talks first to the
	 * service and then to the same selected backend IP/port
	 * directly which can be considered negligible.
	 */
	return get_socket_cookie(ctx);
#else
	return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#endif
}

static __always_inline __maybe_unused
bool sock_proto_enabled(const struct bpf_sock_addr *ctx)
{
	switch (ctx->protocol) {
#ifdef ENABLE_HOST_SERVICES_TCP
	case IPPROTO_TCP:
		return true;
#endif /* ENABLE_HOST_SERVICES_TCP */
#ifdef ENABLE_HOST_SERVICES_UDP
	case IPPROTO_UDPLITE:
	case IPPROTO_UDP:
		return true;
#endif /* ENABLE_HOST_SERVICES_UDP */
	default:
		return false;
	}
}

#ifdef ENABLE_IPV4
#ifdef ENABLE_HOST_SERVICES_UDP
struct ipv4_revnat_tuple {
	__u64 cookie;
	__be32 address;
	__be16 port;
	__u16 pad;
};

struct ipv4_revnat_entry {
	__be32 address;
	__be16 port;
	__u16 rev_nat_index;
};

struct bpf_elf_map __section_maps LB4_REVERSE_NAT_SK_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct ipv4_revnat_tuple),
	.size_value	= sizeof(struct ipv4_revnat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 256 * 1024,
};

static inline int sock4_update_revnat(struct bpf_sock_addr *ctx,
				      struct lb4_backend *backend,
				      struct lb4_key_v2 *lkey,
				      struct lb4_service_v2 *slave_svc)
{
	struct ipv4_revnat_tuple rkey = {};
	struct ipv4_revnat_entry rval = {};

	rkey.cookie = sock_local_cookie(ctx);
	rkey.address = backend->address;
	rkey.port = backend->port;

	rval.address = lkey->address;
	rval.port = lkey->dport;
	rval.rev_nat_index = slave_svc->rev_nat_index;

	return map_update_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey,
			       &rval, 0);
}
#else
static inline int sock4_update_revnat(struct bpf_sock_addr *ctx,
				      struct lb4_backend *backend,
				      struct lb4_key_v2 *lkey,
				      struct lb4_service_v2 *slave_svc)
{
	return -1;
}
#endif /* ENABLE_HOST_SERVICES_UDP */

static inline void sock4_handle_node_port(struct bpf_sock_addr *ctx,
					  struct lb4_key_v2 *key)
{
#ifdef ENABLE_NODEPORT
	struct remote_endpoint_info *info;
	__be32 daddr = ctx->user_ip4;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX)
		goto out_fill_addr;

	/* When connecting to node port services in our cluster that
	 * have either HOST_ID or loopback address, we do a wild-card
	 * lookup with IP of 0.
	 */
	if (is_v4_loopback(daddr))
		return;

	info = ipcache_lookup4(&IPCACHE_MAP, daddr, V4_CACHE_KEY_LEN);
	if (info != NULL && info->sec_label == HOST_ID)
		return;

	/* For everything else in terms of node port, do a direct lookup. */
out_fill_addr:
	key->address = daddr;
#else
	key->address = ctx->user_ip4;
#endif /* ENABLE_NODEPORT */
}

__section("from-sock4")
int sock4_xlate(struct bpf_sock_addr *ctx)
{
	struct lb4_backend *backend;
	struct lb4_service_v2 *svc;
	struct lb4_key_v2 key = {
		.dport		= ctx_get_port(ctx),
	};
	struct lb4_service_v2 *slave_svc;

	if (!sock_proto_enabled(ctx))
		return CONNECT_PROCEED;

	sock4_handle_node_port(ctx, &key);

	svc = __lb4_lookup_service_v2(&key);
	if (svc) {
		key.slave = (sock_local_cookie(ctx) % svc->count) + 1;

		slave_svc = __lb4_lookup_slave_v2(&key);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return CONNECT_PROCEED;
		}

		backend = __lb4_lookup_backend(slave_svc->backend_id);
		if (!backend) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
			return CONNECT_PROCEED;
		}

		if (ctx->protocol != IPPROTO_TCP &&
		    sock4_update_revnat(ctx, backend, &key,
					slave_svc) < 0) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
			return CONNECT_PROCEED;
		}

		ctx->user_ip4	= backend->address;
		ctx_set_port(ctx, backend->port);
	}

	return CONNECT_PROCEED;
}

#ifdef ENABLE_HOST_SERVICES_UDP
__section("snd-sock4")
int sock4_xlate_snd(struct bpf_sock_addr *ctx)
{
	struct lb4_key_v2 lkey = {
		.dport		= ctx_get_port(ctx),
	};
	struct lb4_backend *backend;
	struct lb4_service_v2 *svc;
	struct lb4_service_v2 *slave_svc;

	sock4_handle_node_port(ctx, &lkey);

	svc = __lb4_lookup_service_v2(&lkey);
	if (svc) {
		lkey.slave = (sock_local_cookie(ctx) % svc->count) + 1;

		slave_svc = __lb4_lookup_slave_v2(&lkey);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return SENDMSG_PROCEED;
		}

		backend = __lb4_lookup_backend(slave_svc->backend_id);
		if (!backend) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
			return SENDMSG_PROCEED;
		}

		if (sock4_update_revnat(ctx, backend, &lkey,
					slave_svc) < 0) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
			return SENDMSG_PROCEED;
		}

		ctx->user_ip4 = backend->address;
		ctx_set_port(ctx, backend->port);
	}

	return SENDMSG_PROCEED;
}

__section("rcv-sock4")
int sock4_xlate_rcv(struct bpf_sock_addr *ctx)
{
	struct ipv4_revnat_entry *rval;
	struct ipv4_revnat_tuple rkey = {
		.cookie		= sock_local_cookie(ctx),
		.address	= ctx->user_ip4,
		.port		= ctx_get_port(ctx),
	};

	rval = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey);
	if (rval) {
		struct lb4_service_v2 *svc;
		struct lb4_key_v2 lkey = {
			.address	= rval->address,
			.dport		= rval->port,
		};

		svc = __lb4_lookup_service_v2(&lkey);
		if (!svc || svc->rev_nat_index != rval->rev_nat_index) {
			map_delete_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return RECVMSG_PROCEED;
		}

		ctx->user_ip4 = rval->address;
		ctx_set_port(ctx, rval->port);
	}

	return RECVMSG_PROCEED;
}
#endif /* ENABLE_HOST_SERVICES_UDP */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_HOST_SERVICES_UDP
struct ipv6_revnat_tuple {
	__u64 cookie;
	union v6addr address;
	__be16 port;
	__u16 pad;
};

struct ipv6_revnat_entry {
	union v6addr address;
	__be16 port;
	__u16 rev_nat_index;
};

struct bpf_elf_map __section_maps LB6_REVERSE_NAT_SK_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct ipv6_revnat_tuple),
	.size_value	= sizeof(struct ipv6_revnat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 256 * 1024,
};

static inline int sock6_update_revnat(struct bpf_sock_addr *ctx,
				      struct lb6_backend *backend,
				      struct lb6_key_v2 *lkey,
				      struct lb6_service_v2 *slave_svc)
{
	struct ipv6_revnat_tuple rkey = {};
	struct ipv6_revnat_entry rval = {};

	rkey.cookie = sock_local_cookie(ctx);
	rkey.address = backend->address;
	rkey.port = backend->port;

	rval.address = lkey->address;
	rval.port = lkey->dport;
	rval.rev_nat_index = slave_svc->rev_nat_index;

	return map_update_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey,
			       &rval, 0);
}
#else
static inline int sock6_update_revnat(struct bpf_sock_addr *ctx,
				      struct lb6_backend *backend,
				      struct lb6_key_v2 *lkey,
				      struct lb6_service_v2 *slave_svc)
{
	return -1;
}
#endif /* ENABLE_HOST_SERVICES_UDP */

static __always_inline void ctx_get_v6_address(struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	addr->p1 = ctx->user_ip6[0];
	addr->p2 = ctx->user_ip6[1];
	addr->p3 = ctx->user_ip6[2];
	addr->p4 = ctx->user_ip6[3];
}

static __always_inline void ctx_set_v6_address(struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	ctx->user_ip6[0] = addr->p1;
	ctx->user_ip6[1] = addr->p2;
	ctx->user_ip6[2] = addr->p3;
	ctx->user_ip6[3] = addr->p4;
}

static inline void sock6_handle_node_port(struct bpf_sock_addr *ctx,
					  struct lb6_key_v2 *key)
{
#ifdef ENABLE_NODEPORT
	struct remote_endpoint_info *info;
	union v6addr daddr;
	__u16 service_port;

	ctx_get_v6_address(ctx, &daddr);

	service_port = bpf_ntohs(key->dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX)
		goto out_fill_addr;

	/* When connecting to node port services in our cluster that
	 * have either HOST_ID or loopback address, we do a wild-card
	 * lookup with IP of 0.
	 */
	if (is_v6_loopback(&daddr))
		return;

	info = ipcache_lookup6(&IPCACHE_MAP, &daddr, V6_CACHE_KEY_LEN);
	if (info != NULL && info->sec_label == HOST_ID)
		return;

	/* For everything else in terms of node port, do a direct lookup. */
out_fill_addr:
	key->address = daddr;
#else
	ctx_get_v6_address(ctx, &key->address);
#endif /* ENABLE_NODEPORT */
}

__section("from-sock6")
int sock6_xlate(struct bpf_sock_addr *ctx)
{
	struct lb6_backend *backend;
	struct lb6_service_v2 *svc;
	struct lb6_key_v2 key = {
		.dport		= ctx_get_port(ctx),
	};
	struct lb6_service_v2 *slave_svc;

	if (!sock_proto_enabled(ctx))
		return CONNECT_PROCEED;

	sock6_handle_node_port(ctx, &key);

	svc = __lb6_lookup_service_v2(&key);
	if (svc) {
		key.slave = (sock_local_cookie(ctx) % svc->count) + 1;

		slave_svc = __lb6_lookup_slave_v2(&key);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return CONNECT_PROCEED;
		}

		backend = __lb6_lookup_backend(slave_svc->backend_id);
		if (!backend) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
			return CONNECT_PROCEED;
		}

		if (ctx->protocol != IPPROTO_TCP &&
		    sock6_update_revnat(ctx, backend, &key,
				        slave_svc) < 0) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
			return CONNECT_PROCEED;
		}

		ctx_set_v6_address(ctx, &backend->address);
		ctx_set_port(ctx, backend->port);
	}

	return CONNECT_PROCEED;
}

#ifdef ENABLE_HOST_SERVICES_UDP
__section("snd-sock6")
int sock6_xlate_snd(struct bpf_sock_addr *ctx)
{
	struct lb6_backend *backend;
	struct lb6_service_v2 *svc;
	struct lb6_key_v2 lkey = {
		.dport		= ctx_get_port(ctx),
	};
	struct lb6_service_v2 *slave_svc;

	sock6_handle_node_port(ctx, &lkey);

	svc = __lb6_lookup_service_v2(&lkey);
	if (svc) {
		lkey.slave = (sock_local_cookie(ctx) % svc->count) + 1;

		slave_svc = __lb6_lookup_slave_v2(&lkey);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return CONNECT_PROCEED;
		}

		backend = __lb6_lookup_backend(slave_svc->backend_id);
		if (!backend) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
			return CONNECT_PROCEED;
		}

		if (sock6_update_revnat(ctx, backend, &lkey,
				        slave_svc) < 0) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
			return CONNECT_PROCEED;
		}

		ctx_set_v6_address(ctx, &backend->address);
		ctx_set_port(ctx, backend->port);
	}

	return CONNECT_PROCEED;
}

__section("rcv-sock6")
int sock6_xlate_rcv(struct bpf_sock_addr *ctx)
{
	struct ipv6_revnat_tuple rkey = {};
	struct ipv6_revnat_entry *rval;

	rkey.cookie = sock_local_cookie(ctx);
	rkey.port = ctx_get_port(ctx);
	ctx_get_v6_address(ctx, &rkey.address);

	rval = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey);
	if (rval) {
		struct lb6_service_v2 *svc;
		struct lb6_key_v2 lkey = {
			.address	= rval->address,
			.dport		= rval->port,
		};

		svc = __lb6_lookup_service_v2(&lkey);
		if (!svc || svc->rev_nat_index != rval->rev_nat_index) {
			map_delete_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return RECVMSG_PROCEED;
		}

		ctx_set_v6_address(ctx, &rval->address);
		ctx_set_port(ctx, rval->port);
	}

	return RECVMSG_PROCEED;
}
#endif /* ENABLE_HOST_SERVICES_UDP */
#endif /* ENABLE_IPV6 */

BPF_LICENSE("GPL");
