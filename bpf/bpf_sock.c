// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#define SKIP_POLICY_MAP	1
#define SKIP_CALLS_MAP	1

#include "lib/common.h"
#include "lib/lb.h"
#include "lib/eps.h"
#include "lib/identity.h"
#include "lib/metrics.h"
#include "lib/nat_46x64.h"
#include "lib/trace_sock.h"

#define SYS_REJECT	0
#define SYS_PROCEED	1

#ifndef HOST_NETNS_COOKIE
# define HOST_NETNS_COOKIE   get_netns_cookie(NULL)
#endif

static __always_inline __maybe_unused bool is_v4_loopback(__be32 daddr)
{
	/* Check for 127.0.0.0/8 range, RFC3330. */
	return (daddr & bpf_htonl(0x7f000000)) == bpf_htonl(0x7f000000);
}

static __always_inline __maybe_unused bool is_v6_loopback(const union v6addr *daddr)
{
	/* Check for ::1/128, RFC4291. */
	union v6addr loopback = { .addr[15] = 1, };

	return ipv6_addrcmp(&loopback, daddr) == 0;
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
	volatile __u16 sport = (__u16)ctx->src_port;

	return (__be16)bpf_htons(sport);
}

static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

static __always_inline __maybe_unused bool task_in_extended_hostns(void)
{
#ifdef ENABLE_MKE
	/* Extension for non-Cilium managed containers on MKE. */
	return get_cgroup_classid() == MKE_HOST;
#else
	return false;
#endif
}

static __always_inline __maybe_unused bool
ctx_in_hostns(void *ctx __maybe_unused, __net_cookie *cookie)
{
#ifdef HAVE_NETNS_COOKIE
	__net_cookie own_cookie = get_netns_cookie(ctx);

	if (cookie)
		*cookie = own_cookie;
	return own_cookie == HOST_NETNS_COOKIE ||
	       task_in_extended_hostns();
#else
	if (cookie)
		*cookie = 0;
	return true;
#endif
}

static __always_inline __maybe_unused
bool sock_is_health_check(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_HEALTH_CHECK
	int val;

	if (!get_socket_opt(ctx, SOL_SOCKET, SO_MARK, &val, sizeof(val)))
		return val == MARK_MAGIC_HEALTH;
#endif
	return false;
}

static __always_inline __maybe_unused
__u64 sock_select_slot(struct bpf_sock_addr *ctx)
{
	return ctx->protocol == IPPROTO_TCP ?
	       get_prandom_u32() : sock_local_cookie(ctx);
}

static __always_inline __maybe_unused
bool sock_proto_enabled(__u32 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return true;
	case IPPROTO_UDPLITE:
	case IPPROTO_UDP:
		return true;
	default:
		return false;
	}
}

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_revnat_tuple);
	__type(value, struct ipv4_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
} LB4_REVERSE_NAT_SK_MAP __section_maps_btf;

static __always_inline int sock4_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb4_backend *backend,
					       const struct lb4_key *orig_key,
					       __u16 rev_nat_id)
{
	struct ipv4_revnat_entry val = {}, *tmp;
	struct ipv4_revnat_tuple key = {};
	int ret = 0;

	key.cookie = sock_local_cookie(ctx);
	key.address = backend->address;
	key.port = backend->port;

	val.address = orig_key->address;
	val.port = orig_key->dport;
	val.rev_nat_index = rev_nat_id;

	tmp = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
	if (!tmp || memcmp(tmp, &val, sizeof(val)))
		ret = map_update_elem(&LB4_REVERSE_NAT_SK_MAP, &key,
				      &val, 0);
	return ret;
}

static __always_inline bool
sock4_skip_xlate(struct lb4_service *svc, __be32 address)
{
	if (lb4_to_lb6_service(svc))
		return true;
	if (lb4_svc_is_external_ip(svc) ||
	    (lb4_svc_is_hostport(svc) && !is_v4_loopback(address))) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup4(&IPCACHE_MAP, address,
				       V4_CACHE_KEY_LEN, 0);
		if (!info || info->sec_identity != HOST_ID)
			return true;
	}

	return false;
}

#ifdef ENABLE_NODEPORT
static __always_inline struct lb4_service *
sock4_wildcard_lookup(struct lb4_key *key __maybe_unused,
		      const bool include_remote_hosts __maybe_unused,
		      const bool inv_match __maybe_unused,
		      const bool in_hostns __maybe_unused)
{
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if ((service_port < NODEPORT_PORT_MIN ||
	     service_port > NODEPORT_PORT_MAX) ^ inv_match)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v4_loopback(key->address))
		goto wildcard_lookup;

	info = ipcache_lookup4(&IPCACHE_MAP, key->address, V4_CACHE_KEY_LEN, 0);
	if (info && (info->sec_identity == HOST_ID ||
		     (include_remote_hosts && identity_is_remote_node(info->sec_identity))))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	key->address = 0;
	return lb4_lookup_service(key, true, false);
}
#endif /* ENABLE_NODEPORT */

static __always_inline struct lb4_service *
sock4_wildcard_lookup_full(struct lb4_key *key __maybe_unused,
			   const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	/* Save the original address, as the sock4_wildcard_lookup zeroes it */
	bool loopback = is_v4_loopback(key->address);
	__u32 orig_addr = key->address;
	struct lb4_service *svc;

	svc = sock4_wildcard_lookup(key, true, false, in_hostns);
	if (svc && lb4_svc_is_nodeport(svc))
		return svc;

	/*
	 * We perform a wildcard hostport lookup. If the SVC_FLAG_LOOPBACK
	 * flag is set, then this means that the wildcard entry was set up
	 * using a loopback IP address, in which case we only want to allow
	 * connections to loopback addresses
	 */
	key->address = orig_addr;
	svc = sock4_wildcard_lookup(key, false, true, in_hostns);
	if (svc && lb4_svc_is_hostport(svc) && (!lb4_svc_is_loopback(svc) || loopback))
		return svc;
#endif /* ENABLE_NODEPORT */

	return NULL;
}

/* Service translation logic for a local-redirect service can cause packets to
 * be looped back to a service node-local backend after translation. This can
 * happen when the node-local backend itself tries to connect to the service
 * frontend for which it acts as a backend. There are cases where this can break
 * traffic flow if the backend needs to forward the redirected traffic to the
 * actual service frontend. Hence, allow service translation for pod traffic
 * getting redirected to backend (across network namespaces), but skip service
 * translation for backend to itself or another service backend within the same
 * namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
 *
 * For example, in EKS cluster, a local-redirect service exists with the AWS
 * metadata IP, port as the frontend <169.254.169.254, 80> and kiam proxy as a
 * backend Pod. When traffic destined to the frontend originates from the kiam
 * Pod in namespace ns1 (host ns when the kiam proxy Pod is deployed in
 * hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
 * traffic would get looped back to the proxy Pod. Identify such cases by doing
 * a socket lookup for the backend <ip, port> in its namespace, ns1, and skip
 * service translation.
 */
static __always_inline bool
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx __maybe_unused,
			       const struct lb4_backend *backend __maybe_unused)
{
#ifdef HAVE_SOCKET_LOOKUP
	struct bpf_sock_tuple tuple = {
		.ipv4.daddr = backend->address,
		.ipv4.dport = backend->port,
	};
	struct bpf_sock *sk = NULL;

	switch (ctx->protocol) {
	case IPPROTO_TCP:
		sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	case IPPROTO_UDP:
		sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	}

	if (sk) {
		sk_release(sk);
		return true;
	}
#endif /* HAVE_SOCKET_LOOKUP */
	return false;
}

static __always_inline int __sock4_xlate_fwd(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full,
					     const bool udp_only)
{
	union lb4_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx_full, &id.client_cookie);
	struct lb4_backend *backend;
	struct lb4_service *svc;
	__u16 dst_port = ctx_dst_port(ctx);
	__u32 dst_ip = ctx->user_ip4;
	struct lb4_key key = {
		.address	= dst_ip,
		.dport		= dst_port,
	}, orig_key = key;
	struct lb4_service *backend_slot;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;
#ifdef ENABLE_L7_LB
	struct lb4_backend l7backend;
#endif

	if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)
		return -ENXIO;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	/* In case a direct match fails, we try to look-up surrogate
	 * service entries via wildcarded lookup for NodePort and
	 * HostPort services.
	 */
	svc = lb4_lookup_service(&key, true, false);
	if (!svc)
		svc = sock4_wildcard_lookup_full(&key, in_hostns);
	if (!svc)
		return -ENXIO;
	if (svc->count == 0 && !lb4_svc_is_l7loadbalancer(svc))
		return -EHOSTUNREACH;

	send_trace_sock_notify4(ctx_full, XLATE_PRE_DIRECTION_FWD, dst_ip,
				bpf_ntohs(dst_port));

	/* Do not perform service translation for external IPs
	 * that are not a local address because we don't want
	 * a k8s service to easily do MITM attacks for a public
	 * IP address. But do the service translation if the IP
	 * is from the host.
	 */
	if (sock4_skip_xlate(svc, orig_key.address))
		return -EPERM;

#ifdef ENABLE_L7_LB
	/* Do not perform service translation at socker layer for
	 * services with L7 load balancing as we need to postpone
	 * policy enforcement to take place after l7 load balancer and
	 * we can't currently do that from the socket layer.
	 */
	if (lb4_svc_is_l7loadbalancer(svc)) {
		/* TC level eBPF datapath does not handle node local traffic,
		 * but we need to redirect for L7 LB also in that case.
		 */
		if (is_defined(HAVE_NETNS_COOKIE) && in_hostns) {
			/* Use the L7 LB proxy port as a backend. Normally this
			 * would cause policy enforcement to be done before the
			 * L7 LB (which should not be done), but in this case
			 * (node-local nodeport) there is no policy enforcement
			 * anyway.
			 */
			l7backend.address = bpf_htonl(0x7f000001);
			l7backend.port = (__be16)svc->l7_lb_proxy_port;
			l7backend.proto = 0;
			l7backend.flags = 0;
			backend = &l7backend;
			goto out;
		}
		/* Let the TC level eBPF datapath redirect to L7 LB. */
		return 0;
	}
#endif /* ENABLE_L7_LB */

	if (lb4_svc_is_affinity(svc)) {
		/* Note, for newly created affinity entries there is a
		 * small race window. Two processes on two different
		 * CPUs but the same netns may select different backends
		 * for the same service:port. lb4_update_affinity_by_netns()
		 * below would then override the first created one if it
		 * didn't make it into the lookup yet for the other CPU.
		 */
		backend_id = lb4_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;

		if (backend_id != 0) {
			backend = __lb4_lookup_backend(backend_id);
			if (!backend)
				/* Backend from the session affinity no longer
				 * exists, thus select a new one. Also, remove
				 * the affinity, so that if the svc doesn't have
				 * any backend, a subsequent request to the svc
				 * doesn't hit the reselection again.
				 */
				backend_id = 0;
		}
	}

	if (backend_id == 0) {
		backend_from_affinity = false;

		key.backend_slot = (sock_select_slot(ctx_full) % svc->count) + 1;
		backend_slot = __lb4_lookup_backend_slot(&key);
		if (!backend_slot) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
			return -EHOSTUNREACH;
		}

		backend_id = backend_slot->backend_id;
		backend = __lb4_lookup_backend(backend_id);
	}

	if (!backend) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -EHOSTUNREACH;
	}

	if (lb4_svc_is_localredirect(svc) &&
	    sock4_skip_xlate_if_same_netns(ctx_full, backend))
		return -ENXIO;

	if (lb4_svc_is_affinity(svc) && !backend_from_affinity)
		lb4_update_affinity_by_netns(svc, &id, backend_id);

	send_trace_sock_notify4(ctx_full, XLATE_POST_DIRECTION_FWD, backend->address,
				bpf_ntohs(backend->port));

#ifdef ENABLE_L7_LB
out:
#endif
	if (sock4_update_revnat(ctx_full, backend, &orig_key,
				svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx->user_ip4 = backend->address;
	ctx_set_port(ctx, backend->port);

	return 0;
}

static __always_inline int
__sock4_health_fwd(struct bpf_sock_addr *ctx __maybe_unused)
{
	int ret = lb_skip_l4_dnat() ? SYS_PROCEED : SYS_REJECT;
#ifdef ENABLE_HEALTH_CHECK
	__sock_cookie key = get_socket_cookie(ctx);
	struct lb4_health *val = NULL;

	if (!lb_skip_l4_dnat())
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
	if (val) {
		ctx_set_port(ctx, val->peer.port);
		ret = SYS_PROCEED;
	}
#endif /* ENABLE_HEALTH_CHECK */
	return ret;
}

__section("cgroup/connect4")
int cil_sock4_connect(struct bpf_sock_addr *ctx)
{
	int err;

	if (sock_is_health_check(ctx)) {
		int ret = __sock4_health_fwd(ctx);

		if (ret == SYS_REJECT)
			try_set_retval(-ECONNREFUSED);
		return ret;
	}

	err = __sock4_xlate_fwd(ctx, ctx, false);
	if (err == -EHOSTUNREACH || err == -ENOMEM) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}

#ifdef ENABLE_NODEPORT
static __always_inline int __sock4_post_bind(struct bpf_sock *ctx,
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

	svc = lb4_lookup_service(&key, true, false);
	if (!svc)
		/* Perform a wildcard lookup for the case where the caller
		 * tries to bind to loopback or an address with host identity
		 * (without remote hosts).
		 */
		svc = sock4_wildcard_lookup(&key, false, false, true);

	/* If the sockaddr of this socket overlaps with a NodePort,
	 * LoadBalancer or ExternalIP service. We must reject this
	 * bind() call to avoid accidentally hijacking its traffic.
	 */
	if (svc && (lb4_svc_is_nodeport(svc) ||
		    lb4_svc_is_external_ip(svc) ||
		    lb4_svc_is_loadbalancer(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("cgroup/post_bind4")
int cil_sock4_post_bind(struct bpf_sock *ctx)
{
	int err;

	err = __sock4_post_bind(ctx, ctx);
	if (err < 0) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline void sock4_auto_bind(struct bpf_sock_addr *ctx)
{
	ctx->user_ip4 = 0;
	ctx_set_port(ctx, 0);
}

static __always_inline int __sock4_pre_bind(struct bpf_sock_addr *ctx,
					    struct bpf_sock_addr *ctx_full)
{
	/* Code compiled in here guarantees that get_socket_cookie() is
	 * available and unique on underlying kernel.
	 */
	__sock_cookie key = get_socket_cookie(ctx_full);
	struct lb4_health val = {
		.peer = {
			.address	= ctx->user_ip4,
			.port		= ctx_dst_port(ctx),
			.proto		= (__u8)ctx->protocol,
		},
	};
	int ret;

	ret = map_update_elem(&LB4_HEALTH_MAP, &key, &val, 0);
	if (!ret)
		sock4_auto_bind(ctx);
	return ret;
}

__section("cgroup/bind4")
int cil_sock4_pre_bind(struct bpf_sock_addr *ctx)
{
	int ret = SYS_PROCEED;

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return ret;
	if (sock_is_health_check(ctx) &&
	    __sock4_pre_bind(ctx, ctx)) {
		try_set_retval(-ENOBUFS);
		ret = SYS_REJECT;
	}
	return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

static __always_inline int __sock4_xlate_rev(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full)
{
	struct ipv4_revnat_entry *val;
	__u16 dst_port = ctx_dst_port(ctx);
	__u32 dst_ip = ctx->user_ip4;
	struct ipv4_revnat_tuple key = {
		.cookie		= sock_local_cookie(ctx_full),
		.address	= dst_ip,
		.port		= dst_port,
	};

	send_trace_sock_notify4(ctx_full, XLATE_PRE_DIRECTION_REV, dst_ip,
				bpf_ntohs(dst_port));
	val = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
	if (val) {
		struct lb4_service *svc;
		struct lb4_key svc_key = {
			.address	= val->address,
			.dport		= val->port,
		};

		svc = lb4_lookup_service(&svc_key, true, false);
		if (!svc)
			svc = sock4_wildcard_lookup_full(&svc_key,
						ctx_in_hostns(ctx_full, NULL));
		if (!svc || svc->rev_nat_index != val->rev_nat_index ||
		    (svc->count == 0 && !lb4_svc_is_l7loadbalancer(svc))) {
			map_delete_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx->user_ip4 = val->address;
		ctx_set_port(ctx, val->port);
		send_trace_sock_notify4(ctx_full, XLATE_POST_DIRECTION_REV, val->address,
					bpf_ntohs(val->port));
		return 0;
	}

	return -ENXIO;
}

__section("cgroup/sendmsg4")
int cil_sock4_sendmsg(struct bpf_sock_addr *ctx)
{
	int err;

	err = __sock4_xlate_fwd(ctx, ctx, true);
	if (err == -EHOSTUNREACH || err == -ENOMEM) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}

__section("cgroup/recvmsg4")
int cil_sock4_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}

#ifdef ENABLE_SOCKET_LB_PEER
__section("cgroup/getpeername4")
int cil_sock4_getpeername(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_PEER */

#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPV6) || defined(ENABLE_IPV4)
#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_revnat_tuple);
	__type(value, struct ipv6_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_REVERSE_NAT_SK_MAP_SIZE);
} LB6_REVERSE_NAT_SK_MAP __section_maps_btf;

static __always_inline int sock6_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb6_backend *backend,
					       const struct lb6_key *orig_key,
					       __u16 rev_nat_index)
{
	struct ipv6_revnat_entry val = {}, *tmp;
	struct ipv6_revnat_tuple key = {};
	int ret = 0;

	key.cookie = sock_local_cookie(ctx);
	key.address = backend->address;
	key.port = backend->port;

	val.address = orig_key->address;
	val.port = orig_key->dport;
	val.rev_nat_index = rev_nat_index;

	tmp = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
	if (!tmp || memcmp(tmp, &val, sizeof(val)))
		ret = map_update_elem(&LB6_REVERSE_NAT_SK_MAP, &key,
				      &val, 0);
	return ret;
}
#endif /* ENABLE_IPV6 */

static __always_inline void ctx_get_v6_address(const struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	addr->p1 = ctx->user_ip6[0];
	barrier();
	addr->p2 = ctx->user_ip6[1];
	barrier();
	addr->p3 = ctx->user_ip6[2];
	barrier();
	addr->p4 = ctx->user_ip6[3];
	barrier();
}

#ifdef ENABLE_NODEPORT
static __always_inline void ctx_get_v6_src_address(const struct bpf_sock *ctx,
						   union v6addr *addr)
{
	addr->p1 = ctx->src_ip6[0];
	barrier();
	addr->p2 = ctx->src_ip6[1];
	barrier();
	addr->p3 = ctx->src_ip6[2];
	barrier();
	addr->p4 = ctx->src_ip6[3];
	barrier();
}
#endif /* ENABLE_NODEPORT */

static __always_inline void ctx_set_v6_address(struct bpf_sock_addr *ctx,
					       const union v6addr *addr)
{
	ctx->user_ip6[0] = addr->p1;
	barrier();
	ctx->user_ip6[1] = addr->p2;
	barrier();
	ctx->user_ip6[2] = addr->p3;
	barrier();
	ctx->user_ip6[3] = addr->p4;
	barrier();
}

static __always_inline __maybe_unused bool
sock6_skip_xlate(struct lb6_service *svc, const union v6addr *address)
{
	if (lb6_to_lb4_service(svc))
		return true;
	if (lb6_svc_is_external_ip(svc) ||
	    (lb6_svc_is_hostport(svc) && !is_v6_loopback(address))) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup6(&IPCACHE_MAP, address,
				       V6_CACHE_KEY_LEN, 0);
		if (!info || info->sec_identity != HOST_ID)
			return true;
	}

	return false;
}

#ifdef ENABLE_NODEPORT
static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup(struct lb6_key *key __maybe_unused,
		      const bool include_remote_hosts __maybe_unused,
		      const bool inv_match __maybe_unused,
		      const bool in_hostns __maybe_unused)
{
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if ((service_port < NODEPORT_PORT_MIN ||
	     service_port > NODEPORT_PORT_MAX) ^ inv_match)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v6_loopback(&key->address))
		goto wildcard_lookup;

	info = ipcache_lookup6(&IPCACHE_MAP, &key->address, V6_CACHE_KEY_LEN, 0);
	if (info && (info->sec_identity == HOST_ID ||
		     (include_remote_hosts && identity_is_remote_node(info->sec_identity))))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	memset(&key->address, 0, sizeof(key->address));
	return lb6_lookup_service(key, true, false);
}
#endif /* ENABLE_NODEPORT */

static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup_full(struct lb6_key *key __maybe_unused,
			   const bool in_hostns __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	/* Save the original address, as the sock6_wildcard_lookup zeroes it */
	bool loopback = is_v6_loopback(&key->address);
	union v6addr orig_address;
	struct lb6_service *svc;

	memcpy(&orig_address, &key->address, sizeof(orig_address));
	svc = sock6_wildcard_lookup(key, true, false, in_hostns);
	if (svc && lb6_svc_is_nodeport(svc))
		return svc;

	/* See a corresponding commment in sock4_wildcard_lookup_full */
	memcpy(&key->address, &orig_address, sizeof(orig_address));
	svc = sock6_wildcard_lookup(key, false, true, in_hostns);
	if (svc && lb6_svc_is_hostport(svc) && (!lb6_svc_is_loopback(svc) || loopback))
		return svc;

#endif /* ENABLE_NODEPORT */
	return NULL;
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
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
}

#ifdef ENABLE_NODEPORT
static __always_inline int
sock6_post_bind_v4_in_v6(struct bpf_sock *ctx __maybe_unused)
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

	return __sock4_post_bind(&fake_ctx, ctx);
#endif /* ENABLE_IPV4 */
	return 0;
}

static __always_inline int __sock6_post_bind(struct bpf_sock *ctx)
{
	struct lb6_service *svc;
	struct lb6_key key = {
		.dport		= ctx_src_port(ctx),
	};

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return 0;

	ctx_get_v6_src_address(ctx, &key.address);

	svc = lb6_lookup_service(&key, true, false);
	if (!svc) {
		svc = sock6_wildcard_lookup(&key, false, false, true);
		if (!svc)
			return sock6_post_bind_v4_in_v6(ctx);
	}

	if (svc && (lb6_svc_is_nodeport(svc) ||
		    lb6_svc_is_external_ip(svc) ||
		    lb6_svc_is_loadbalancer(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("cgroup/post_bind6")
int cil_sock6_post_bind(struct bpf_sock *ctx)
{
	int err;

	err = __sock6_post_bind(ctx);
	if (err < 0) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
static __always_inline int
sock6_pre_bind_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_pre_bind(&fake_ctx, ctx);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);
#endif /* ENABLE_IPV4 */
	return 0;
}

#ifdef ENABLE_IPV6
static __always_inline void sock6_auto_bind(struct bpf_sock_addr *ctx)
{
	union v6addr zero = {};

	ctx_set_v6_address(ctx, &zero);
	ctx_set_port(ctx, 0);
}
#endif

static __always_inline int __sock6_pre_bind(struct bpf_sock_addr *ctx)
{
	__sock_cookie key __maybe_unused;
	struct lb6_health val = {
		.peer = {
			.port		= ctx_dst_port(ctx),
			.proto		= (__u8)ctx->protocol,
		},
	};
	int ret = 0;

	ctx_get_v6_address(ctx, &val.peer.address);
	if (is_v4_in_v6(&val.peer.address))
		return sock6_pre_bind_v4_in_v6(ctx);
#ifdef ENABLE_IPV6
	key = get_socket_cookie(ctx);
	ret = map_update_elem(&LB6_HEALTH_MAP, &key, &val, 0);
	if (!ret)
		sock6_auto_bind(ctx);
#endif
	return ret;
}

__section("cgroup/bind6")
int cil_sock6_pre_bind(struct bpf_sock_addr *ctx)
{
	int ret = SYS_PROCEED;

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return ret;
	if (sock_is_health_check(ctx) &&
	    __sock6_pre_bind(ctx)) {
		try_set_retval(-ENOBUFS);
		ret = SYS_REJECT;
	}
	return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

static __always_inline int __sock6_xlate_fwd(struct bpf_sock_addr *ctx,
					     const bool udp_only)
{
#ifdef ENABLE_IPV6
	union lb6_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx, &id.client_cookie);
	struct lb6_backend *backend;
	struct lb6_service *svc;
	__u16 dst_port = ctx_dst_port(ctx);
	struct lb6_key key = {
		.dport		= dst_port,
	}, orig_key;
	struct lb6_service *backend_slot;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;
#ifdef ENABLE_L7_LB
	struct lb6_backend l7backend;
#endif

	if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)
		return -ENXIO;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	ctx_get_v6_address(ctx, &key.address);
	memcpy(&orig_key, &key, sizeof(key));

	svc = lb6_lookup_service(&key, true, false);
	if (!svc)
		svc = sock6_wildcard_lookup_full(&key, in_hostns);
	if (!svc)
		return sock6_xlate_v4_in_v6(ctx, udp_only);
	if (svc->count == 0 && !lb6_svc_is_l7loadbalancer(svc))
		return -EHOSTUNREACH;

	send_trace_sock_notify6(ctx, XLATE_PRE_DIRECTION_FWD, &key.address,
				bpf_ntohs(dst_port));

	if (sock6_skip_xlate(svc, &orig_key.address))
		return -EPERM;

#ifdef ENABLE_L7_LB
	/* See __sock4_xlate_fwd for commentary. */
	if (lb6_svc_is_l7loadbalancer(svc)) {
		if (is_defined(HAVE_NETNS_COOKIE) && in_hostns) {
			union v6addr loopback = { .addr[15] = 1, };

			l7backend.address = loopback;
			l7backend.port = (__be16)svc->l7_lb_proxy_port;
			l7backend.proto = 0;
			l7backend.flags = 0;
			backend = &l7backend;
			goto out;
		}
		return 0;
	}
#endif /* ENABLE_L7_LB */

	if (lb6_svc_is_affinity(svc)) {
		backend_id = lb6_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;

		if (backend_id != 0) {
			backend = __lb6_lookup_backend(backend_id);
			if (!backend)
				backend_id = 0;
		}
	}

	if (backend_id == 0) {
		backend_from_affinity = false;

		key.backend_slot = (sock_select_slot(ctx) % svc->count) + 1;
		backend_slot = __lb6_lookup_backend_slot(&key);
		if (!backend_slot) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
			return -EHOSTUNREACH;
		}

		backend_id = backend_slot->backend_id;
		backend = __lb6_lookup_backend(backend_id);
	}

	if (!backend) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -EHOSTUNREACH;
	}

	if (lb6_svc_is_affinity(svc) && !backend_from_affinity)
		lb6_update_affinity_by_netns(svc, &id, backend_id);

	send_trace_sock_notify6(ctx, XLATE_POST_DIRECTION_FWD, &backend->address,
				bpf_ntohs(backend->port));

#ifdef ENABLE_L7_LB
out:
#endif
	if (sock6_update_revnat(ctx, backend, &orig_key,
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

static __always_inline int
__sock6_health_fwd(struct bpf_sock_addr *ctx __maybe_unused)
{
	int ret = lb_skip_l4_dnat() ? SYS_PROCEED : SYS_REJECT;
#ifdef ENABLE_HEALTH_CHECK
	union v6addr addr6;

	ctx_get_v6_address(ctx, &addr6);
	if (is_v4_in_v6(&addr6)) {
		return __sock4_health_fwd(ctx);
	} else {
#ifdef ENABLE_IPV6
		__sock_cookie key = get_socket_cookie(ctx);
		struct lb6_health *val = NULL;

		if (!lb_skip_l4_dnat())
			val = map_lookup_elem(&LB6_HEALTH_MAP, &key);
		if (val) {
			ctx_set_port(ctx, val->peer.port);
			ret = SYS_PROCEED;
		}
#endif /* ENABLE_IPV6 */
	}
#endif /* ENABLE_HEALTH_CHECK */
	return ret;
}

__section("cgroup/connect6")
int cil_sock6_connect(struct bpf_sock_addr *ctx)
{
	int err;

	if (sock_is_health_check(ctx)) {
		int ret = __sock6_health_fwd(ctx);

		if (ret == SYS_REJECT)
			try_set_retval(-ECONNREFUSED);
		return ret;
	}

	err = __sock6_xlate_fwd(ctx, false);
	if (err == -EHOSTUNREACH || err == -ENOMEM) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}

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
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
}

static __always_inline int __sock6_xlate_rev(struct bpf_sock_addr *ctx)
{
#ifdef ENABLE_IPV6
	struct ipv6_revnat_tuple key = {};
	struct ipv6_revnat_entry *val;
	__u16 dst_port = ctx_dst_port(ctx);

	key.cookie = sock_local_cookie(ctx);
	key.port = dst_port;
	ctx_get_v6_address(ctx, &key.address);

	send_trace_sock_notify6(ctx, XLATE_PRE_DIRECTION_REV, &key.address,
				bpf_ntohs(dst_port));

	val = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
	if (val) {
		struct lb6_service *svc;
		struct lb6_key svc_key = {
			.address	= val->address,
			.dport		= val->port,
		};

		svc = lb6_lookup_service(&svc_key, true, false);
		if (!svc)
			svc = sock6_wildcard_lookup_full(&svc_key,
						ctx_in_hostns(ctx, NULL));
		if (!svc || svc->rev_nat_index != val->rev_nat_index ||
		    (svc->count == 0 && !lb6_svc_is_l7loadbalancer(svc))) {
			map_delete_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx_set_v6_address(ctx, &val->address);
		ctx_set_port(ctx, val->port);
		send_trace_sock_notify6(ctx, XLATE_POST_DIRECTION_REV, &val->address,
					bpf_ntohs(val->port));
		return 0;
	}
#endif /* ENABLE_IPV6 */

	return sock6_xlate_rev_v4_in_v6(ctx);
}

__section("cgroup/sendmsg6")
int cil_sock6_sendmsg(struct bpf_sock_addr *ctx)
{
	int err;

	err = __sock6_xlate_fwd(ctx, true);
	if (err == -EHOSTUNREACH || err == -ENOMEM) {
		try_set_retval(err);
		return SYS_REJECT;
	}

	return SYS_PROCEED;
}

__section("cgroup/recvmsg6")
int cil_sock6_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}

#ifdef ENABLE_SOCKET_LB_PEER
__section("cgroup/getpeername6")
int cil_sock6_getpeername(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_PEER */

#endif /* ENABLE_IPV6 || ENABLE_IPV4 */

BPF_LICENSE("Dual BSD/GPL");
