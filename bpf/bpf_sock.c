// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#define SKIP_POLICY_MAP	1
#define SKIP_CALLS_MAP	1

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/lb.h"
#include "lib/eps.h"
#include "lib/metrics.h"

#define SYS_REJECT	0
#define SYS_PROCEED	1

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

static __always_inline __maybe_unused bool is_v4_in_v6(const union v6addr *daddr)
{
	/* Check for ::FFFF:<IPv4 address>. */
	union v6addr dprobe  = {
		.addr[10] = 0xff,
		.addr[11] = 0xff,
	};
	union v6addr dmasked = {
		.d1 = daddr->d1,
	};
	dmasked.p3 = daddr->p3;
	return ipv6_addrcmp(&dprobe, &dmasked) == 0;
}

static __always_inline __maybe_unused void build_v4_in_v6(union v6addr *daddr,
							  __be32 v4)
{
	memset(daddr, 0, sizeof(*daddr));
	daddr->addr[10] = 0xff;
	daddr->addr[11] = 0xff;
	daddr->p4 = v4;
}

/* Hack due to missing narrow ctx access. */
static __always_inline __maybe_unused __be16
ctx_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;
	return (__be16)dport;
}

static __always_inline __maybe_unused __be16
ctx_src_port(const struct bpf_sock *ctx)
{
	volatile __u32 sport = ctx->src_port;
	return (__be16)bpf_htons(sport);
}

static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

static __always_inline __maybe_unused bool
ctx_in_hostns(void *ctx __maybe_unused, __u64 *cookie)
{
#ifdef BPF_HAVE_NETNS_COOKIE
	__u64 own_cookie = get_netns_cookie(ctx);

	if (cookie)
		*cookie = own_cookie;
	return own_cookie == get_netns_cookie(NULL);
#else
	if (cookie)
		*cookie = 0;
	return true;
#endif
}

static __always_inline __maybe_unused
__u64 sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef BPF_HAVE_SOCKET_COOKIE
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
bool sock_proto_enabled(__u32 proto)
{
	switch (proto) {
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
#if defined(ENABLE_HOST_SERVICES_UDP) || defined(ENABLE_HOST_SERVICES_PEER)
struct bpf_elf_map __section_maps LB4_REVERSE_NAT_SK_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct ipv4_revnat_tuple),
	.size_value	= sizeof(struct ipv4_revnat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LB4_REVERSE_NAT_SK_MAP_SIZE,
};

static __always_inline int sock4_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb4_backend *backend,
					       const struct lb4_key *lkey,
					       __u16 rev_nat_id)
{
	struct ipv4_revnat_entry rval = {}, *tmp;
	struct ipv4_revnat_tuple rkey = {};
	int ret = 0;

	rkey.cookie = sock_local_cookie(ctx);
	rkey.address = backend->address;
	rkey.port = backend->port;

	rval.address = lkey->address;
	rval.port = lkey->dport;
	rval.rev_nat_index = rev_nat_id;

	tmp = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey);
	if (!tmp || memcmp(tmp, &rval, sizeof(rval)))
		ret = map_update_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey,
				      &rval, 0);
	return ret;
}
#else
static __always_inline
int sock4_update_revnat(struct bpf_sock_addr *ctx __maybe_unused,
			struct lb4_backend *backend __maybe_unused,
			struct lb4_key *lkey __maybe_unused,
			__u16 rev_nat_id __maybe_unused)
{
	return -1;
}
#endif /* ENABLE_HOST_SERVICES_UDP || ENABLE_HOST_SERVICES_PEER */

static __always_inline bool
sock4_skip_xlate(struct lb4_service *svc, const bool in_hostns,
		 __be32 address)
{
	if (is_v4_loopback(address))
		return false;
	if (svc->local_scope || lb4_svc_is_external_ip(svc)) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup4(&IPCACHE_MAP, address,
				       V4_CACHE_KEY_LEN);
		if (info == NULL ||
		    (svc->local_scope && info->sec_label != HOST_ID))
			return true;
		if (lb4_svc_is_external_ip(svc)) {
			if (info->sec_label != HOST_ID &&
			    info->sec_label != REMOTE_NODE_ID)
				return in_hostns;
		}
	}

	return false;
}

static __always_inline struct lb4_service *
sock4_nodeport_wildcard_lookup(struct lb4_key *key __maybe_unused,
			       const bool include_remote_hosts __maybe_unused,
			       const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v4_loopback(key->address))
		goto wildcard_lookup;

	info = ipcache_lookup4(&IPCACHE_MAP, key->address, V4_CACHE_KEY_LEN);
	if (info != NULL && (info->sec_label == HOST_ID ||
	    (include_remote_hosts && info->sec_label == REMOTE_NODE_ID)))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	key->address = 0;
	return lb4_lookup_service(key);
#else
	return NULL;
#endif /* ENABLE_NODEPORT */
}

static __always_inline int __sock4_xlate_fwd(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full,
					     const bool udp_only)
{
	union lb4_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx_full, &id.client_cookie);
	struct lb4_backend *backend;
	struct lb4_service *svc;
	struct lb4_key key = {
		.address	= ctx->user_ip4,
		.dport		= ctx_dst_port(ctx),
	};
	struct lb4_service *slave_svc;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	/* Initial non-wildcarded lookup handles regular services
	 * deployed in nodeport range, external ip and partially
	 * nodeport services. If latter fails, we try wildcarded
	 * lookup for nodeport services.
	 */
	svc = lb4_lookup_service(&key);
	if (!svc) {
		key.dport = ctx_dst_port(ctx);
		svc = sock4_nodeport_wildcard_lookup(&key, true, in_hostns);
		if (svc && !lb4_svc_is_nodeport(svc))
			svc = NULL;
	}
	if (!svc)
		return -ENXIO;

	/* Do not perform service translation for external IPs
	 * that are not a local address because we don't want
	 * a k8s service to easily do MITM attacks for a public
	 * IP address. But do the service translation if the IP
	 * is from the host.
	 */
	if (sock4_skip_xlate(svc, in_hostns, ctx->user_ip4))
		return -EPERM;

	if (svc->affinity) {
		backend_id = lb4_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;
	}

	if (backend_id == 0) {
reselect_backend:
		backend_from_affinity = false;

		key.slave = (sock_local_cookie(ctx_full) % svc->count) + 1;
		slave_svc = __lb4_lookup_slave(&key);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return -ENOENT;
		}

		backend_id = slave_svc->backend_id;
	}

	backend = __lb4_lookup_backend(backend_id);
	if (!backend) {
		if (backend_from_affinity) {
			/* Backend from the session affinity no longer exists,
			 * thus select a new one. Also, remove the affinity,
			 * so that if the svc doesn't have any backend, a
			 * subsequent request to the svc doesn't hit the
			 * reselection again.
			 */
			lb4_delete_affinity_by_netns(svc, &id);
			goto reselect_backend;
		}

		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -ENOENT;
	}

	if (svc->affinity)
		lb4_update_affinity_by_netns(svc, &id, backend_id);

	if (sock4_update_revnat(ctx_full, backend, &key,
				svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx->user_ip4 = backend->address;
	ctx_set_port(ctx, backend->port);

	return 0;
}

__section("connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_fwd(ctx, ctx, false);
	return SYS_PROCEED;
}

#if defined(ENABLE_NODEPORT) || defined(ENABLE_EXTERNAL_IP)
static __always_inline int __sock4_bind(struct bpf_sock *ctx,
					struct bpf_sock *ctx_full)
{
	struct lb4_service *svc;
	struct lb4_key key = {
		.address	= ctx->src_ip4,
		.dport		= ctx_src_port(ctx),
	};

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx_full, NULL))
		return 0;

	svc = lb4_lookup_service(&key);
	if (!svc) {
		/* Perform a wildcard lookup for the case where the caller tries
		 * to bind to loopback or an address with host identity
		 * (without remote hosts).
		 */
		key.dport = ctx_src_port(ctx);
		svc = sock4_nodeport_wildcard_lookup(&key, false, true);
	}

	/* If the sockaddr of this socket overlaps with a NodePort
	 * or ExternalIP service. We must reject this bind() call
	 * to avoid accidentally hijacking its traffic.
	 */
	if (svc && (lb4_svc_is_nodeport(svc) || lb4_svc_is_external_ip(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("post_bind4")
int sock4_bind(struct bpf_sock *ctx)
{
	if (__sock4_bind(ctx, ctx) < 0)
		return SYS_REJECT;

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT || ENABLE_EXTERNAL_IP */

#if defined(ENABLE_HOST_SERVICES_UDP) || defined(ENABLE_HOST_SERVICES_PEER)
static __always_inline int __sock4_xlate_rev(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full)
{
	struct ipv4_revnat_entry *rval;
	struct ipv4_revnat_tuple rkey = {
		.cookie		= sock_local_cookie(ctx_full),
		.address	= ctx->user_ip4,
		.port		= ctx_dst_port(ctx),
	};

	rval = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey);
	if (rval) {
		struct lb4_service *svc;
		struct lb4_key lkey = {
			.address	= rval->address,
			.dport		= rval->port,
		};

		svc = lb4_lookup_service(&lkey);
		if (!svc || svc->rev_nat_index != rval->rev_nat_index) {
			map_delete_elem(&LB4_REVERSE_NAT_SK_MAP, &rkey);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx->user_ip4 = rval->address;
		ctx_set_port(ctx, rval->port);
		return 0;
	}

	return -ENXIO;
}

__section("sendmsg4")
int sock4_sendmsg(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_fwd(ctx, ctx, true);
	return SYS_PROCEED;
}

__section("recvmsg4")
int sock4_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}

__section("getpeername4")
int sock4_getpeername(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_HOST_SERVICES_UDP || ENABLE_HOST_SERVICES_PEER */
#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPV6) || defined(ENABLE_IPV4)
#ifdef ENABLE_IPV6
#if defined(ENABLE_HOST_SERVICES_UDP) || defined(ENABLE_HOST_SERVICES_PEER)
struct bpf_elf_map __section_maps LB6_REVERSE_NAT_SK_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct ipv6_revnat_tuple),
	.size_value	= sizeof(struct ipv6_revnat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= LB6_REVERSE_NAT_SK_MAP_SIZE,
};

static __always_inline int sock6_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb6_backend *backend,
					       const struct lb6_key *lkey,
					       __u16 rev_nat_index)
{
	struct ipv6_revnat_entry rval = {}, *tmp;
	struct ipv6_revnat_tuple rkey = {};
	int ret = 0;

	rkey.cookie = sock_local_cookie(ctx);
	rkey.address = backend->address;
	rkey.port = backend->port;

	rval.address = lkey->address;
	rval.port = lkey->dport;
	rval.rev_nat_index = rev_nat_index;

	tmp = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey);
	if (!tmp || memcmp(tmp, &rval, sizeof(rval)))
		ret = map_update_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey,
				      &rval, 0);
	return ret;
}
#else
static __always_inline
int sock6_update_revnat(struct bpf_sock_addr *ctx __maybe_unused,
			struct lb6_backend *backend __maybe_unused,
			struct lb6_key *lkey __maybe_unused,
			__u16 rev_nat_index __maybe_unused)
{
	return -1;
}
#endif /* ENABLE_HOST_SERVICES_UDP || ENABLE_HOST_SERVICES_PEER */
#endif /* ENABLE_IPV6 */

static __always_inline void ctx_get_v6_address(const struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	addr->p1 = ctx->user_ip6[0];
	addr->p2 = ctx->user_ip6[1];
	addr->p3 = ctx->user_ip6[2];
	addr->p4 = ctx->user_ip6[3];
}

#ifdef ENABLE_NODEPORT
static __always_inline void ctx_get_v6_src_address(const struct bpf_sock *ctx,
						   union v6addr *addr)
{
	addr->p1 = ctx->src_ip6[0];
	addr->p2 = ctx->src_ip6[1];
	addr->p3 = ctx->src_ip6[2];
	addr->p4 = ctx->src_ip6[3];
}
#endif /* ENABLE_NODEPORT */

static __always_inline void ctx_set_v6_address(struct bpf_sock_addr *ctx,
					       const union v6addr *addr)
{
	ctx->user_ip6[0] = addr->p1;
	ctx->user_ip6[1] = addr->p2;
	ctx->user_ip6[2] = addr->p3;
	ctx->user_ip6[3] = addr->p4;
}

static __always_inline __maybe_unused bool
sock6_skip_xlate(struct lb6_service *svc, const bool in_hostns,
		 union v6addr *address)
{
	if (is_v6_loopback(address))
		return false;
	if (svc->local_scope || lb6_svc_is_external_ip(svc)) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup6(&IPCACHE_MAP, address,
				       V6_CACHE_KEY_LEN);
		if (info == NULL ||
		    (svc->local_scope && info->sec_label != HOST_ID))
			return true;
		if (lb6_svc_is_external_ip(svc)) {
			if (info->sec_label != HOST_ID &&
			    info->sec_label != REMOTE_NODE_ID)
				return in_hostns;
		}
	}

	return false;
}

static __always_inline __maybe_unused struct lb6_service *
sock6_nodeport_wildcard_lookup(struct lb6_key *key __maybe_unused,
			       const bool include_remote_hosts __maybe_unused,
			       const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v6_loopback(&key->address))
		goto wildcard_lookup;

	info = ipcache_lookup6(&IPCACHE_MAP, &key->address, V6_CACHE_KEY_LEN);
	if (info != NULL && (info->sec_label == HOST_ID ||
	    (include_remote_hosts && info->sec_label == REMOTE_NODE_ID)))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	memset(&key->address, 0, sizeof(key->address));
	return lb6_lookup_service(key);
#else
	return NULL;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
int sock6_xlate_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused,
			 const bool udp_only __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return -ENXIO;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_xlate_fwd(&fake_ctx, ctx, udp_only);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
}

#if defined(ENABLE_NODEPORT) || defined(ENABLE_EXTERNAL_IP)
static __always_inline int
sock6_bind_v4_in_v6(struct bpf_sock *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock fake_ctx;
	union v6addr addr6;

	ctx_get_v6_src_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return 0;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol = ctx->protocol;
	fake_ctx.src_ip4  = addr6.p4;
	fake_ctx.src_port = ctx->src_port;

	return __sock4_bind(&fake_ctx, ctx);
#endif /* ENABLE_IPV4 */
	return 0;
}

static __always_inline int __sock6_bind(struct bpf_sock *ctx)
{
	struct lb6_service *svc;
	struct lb6_key key = {
		.dport		= ctx_src_port(ctx),
	};

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return 0;

	ctx_get_v6_src_address(ctx, &key.address);

	svc = lb6_lookup_service(&key);
	if (!svc) {
		key.dport = ctx_src_port(ctx);
		svc = sock6_nodeport_wildcard_lookup(&key, false, true);
		if (!svc)
			return sock6_bind_v4_in_v6(ctx);
	}

	if (svc && (lb6_svc_is_nodeport(svc) || lb6_svc_is_external_ip(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("post_bind6")
int sock6_bind(struct bpf_sock *ctx)
{
	if (__sock6_bind(ctx) < 0)
		return SYS_REJECT;

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT || ENABLE_EXTERNAL_IP */

static __always_inline int __sock6_xlate_fwd(struct bpf_sock_addr *ctx,
					     const bool udp_only)
{
#ifdef ENABLE_IPV6
	union lb6_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx, &id.client_cookie);
	struct lb6_backend *backend;
	struct lb6_service *svc;
	struct lb6_key key = {
		.dport		= ctx_dst_port(ctx),
	};
	struct lb6_service *slave_svc;
	union v6addr v6_orig;
	__u32 backend_id = 0;
	bool backend_from_affinity = false;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	ctx_get_v6_address(ctx, &key.address);
	v6_orig = key.address;

	svc = lb6_lookup_service(&key);
	if (!svc) {
		key.dport = ctx_dst_port(ctx);
		svc = sock6_nodeport_wildcard_lookup(&key, true, in_hostns);
		if (svc && !lb6_svc_is_nodeport(svc))
			svc = NULL;
		else if (!svc)
			return sock6_xlate_v4_in_v6(ctx, udp_only);
	}
	if (!svc)
		return -ENXIO;

	if (sock6_skip_xlate(svc, in_hostns, &v6_orig))
		return -EPERM;

	if (svc->affinity) {
		backend_id = lb6_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;
	}

	if (backend_id == 0) {
reselect_backend:
		backend_from_affinity = false;

		key.slave = (sock_local_cookie(ctx) % svc->count) + 1;
		slave_svc = __lb6_lookup_slave(&key);
		if (!slave_svc) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_SLAVE);
			return -ENOENT;
		}

		backend_id = slave_svc->backend_id;
	}

	backend = __lb6_lookup_backend(backend_id);
	if (!backend) {
		if (backend_from_affinity) {
			lb6_delete_affinity_by_netns(svc, &id);
			goto reselect_backend;
		}

		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -ENOENT;
	}

	if (svc->affinity)
		lb6_update_affinity_by_netns(svc, &id, backend_id);

	if (sock6_update_revnat(ctx, backend, &key,
			        svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx_set_v6_address(ctx, &backend->address);
	ctx_set_port(ctx, backend->port);

	return 0;
#else
	return sock6_xlate_v4_in_v6(ctx, udp_only);
#endif /* ENABLE_IPV6 */
}

__section("connect6")
int sock6_connect(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_fwd(ctx, false);
	return SYS_PROCEED;
}

#if defined(ENABLE_HOST_SERVICES_UDP) || defined(ENABLE_HOST_SERVICES_PEER)
static __always_inline int
sock6_xlate_rev_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return -ENXIO;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_xlate_rev(&fake_ctx, ctx);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
}

static __always_inline int __sock6_xlate_rev(struct bpf_sock_addr *ctx)
{
#ifdef ENABLE_IPV6
	struct ipv6_revnat_tuple rkey = {};
	struct ipv6_revnat_entry *rval;

	rkey.cookie = sock_local_cookie(ctx);
	rkey.port = ctx_dst_port(ctx);
	ctx_get_v6_address(ctx, &rkey.address);

	rval = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey);
	if (rval) {
		struct lb6_service *svc;
		struct lb6_key lkey = {
			.address	= rval->address,
			.dport		= rval->port,
		};

		svc = lb6_lookup_service(&lkey);
		if (!svc || svc->rev_nat_index != rval->rev_nat_index) {
			map_delete_elem(&LB6_REVERSE_NAT_SK_MAP, &rkey);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx_set_v6_address(ctx, &rval->address);
		ctx_set_port(ctx, rval->port);
		return 0;
	}
#endif /* ENABLE_IPV6 */

	return sock6_xlate_rev_v4_in_v6(ctx);
}

__section("sendmsg6")
int sock6_sendmsg(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_fwd(ctx, true);
	return SYS_PROCEED;
}

__section("recvmsg6")
int sock6_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}

__section("getpeername6")
int sock6_getpeername(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_HOST_SERVICES_UDP || ENABLE_HOST_SERVICES_PEER */
#endif /* ENABLE_IPV6 || ENABLE_IPV4 */

BPF_LICENSE("GPL");
