// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include "common.h"
#include "pktgen.h"

#define TEST_BPF_SOCK 1

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#undef ENABLE_HEALTH_CHECK
#define ENABLE_LOCAL_REDIRECT_POLICY 1

#define BACKEND_PORT 7000
#define NETNS_COOKIE 5000
#define NETNS_COOKIE2 5001
#define HOST_NETNS_COOKIE 0
#define DST_PORT 6000
#define V6_BACKEND1 v6_pod_one
#define V6_SVC_ONE v6_node_one
#define V6_SVC_TWO v6_node_two

#define get_netns_cookie(ctx) test_get_netns_cookie(ctx)
/* Set netns_cookie based on the source ip in the addr. While this field isn't
 * populated in real CGROUP_SOCK_ADDR hooks, we use it only for testing to
 * mock netns_cookies for different source pods.
 */
static __always_inline
int test_get_netns_cookie(__maybe_unused const struct bpf_sock_addr *addr)
{
	struct bpf_sock *sk = addr->sk;

	if (!sk)
		return 0;
	if (sk->src_ip4 == v4_pod_one ||
	    (sk->src_ip6[0] == bpf_htonl(0xfd040000) &&
	     sk->src_ip6[1] == 0 &&
	     sk->src_ip6[2] == 0 &&
	     sk->src_ip6[3] == bpf_htonl(1)))
		return NETNS_COOKIE;
	else
		return NETNS_COOKIE2;
}

#include "bpf_sock.c"
#include "lib/common.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

CHECK("xdp", "sock4_xlate_fwd")
int test_sock4_xlate_fwd_skip_lb(__maybe_unused struct xdp_md *ctx)
{
	int ret;
	__u16 revnat_id = 1;
	__u16 revnat_id2 = 2;
	struct bpf_sock sk = {
		.src_ip4 = v4_pod_one
	};
	struct bpf_sock_addr addr = {
		.user_port = tcp_svc_one,
		.protocol = IPPROTO_TCP,
		.sk = &sk,
	};
	struct skip_lb4_key key = {
		.netns_cookie = NETNS_COOKIE,
		.address = v4_svc_one,
		.port = tcp_svc_one,
	};
	__u8 val = 0;

	lb_v4_add_service_with_flags(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id,
				     0, SVC_FLAG_LOCALREDIRECT);
	lb_v4_add_service_with_flags(v4_svc_two, tcp_svc_two, IPPROTO_TCP, 1, revnat_id2,
				     0, SVC_FLAG_LOCALREDIRECT);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);
	lb_v4_add_backend(v4_svc_two, tcp_svc_two, 1, 124,
			  v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);
	ret = map_update_elem(&cilium_skip_lb4, &key, &val, BPF_ANY);
	/* Needed to avoid sock4_skip_xlate */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	test_init();

	/* Skip LB xlate when pod_one is connecting to v4_svc_one:tcp_svc_one. */
	addr.user_ip4 = v4_svc_one,
	addr.user_port = tcp_svc_one,
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("ret: %d", ret);
	test_log("pod_one [%lx] -> svc_one [%lx]", addr.sk->src_ip4, addr.user_ip4);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == tcp_svc_one);
	assert(ret == -ENXIO);

	/* LB xlate happens when pod_one is connecting to v4_svc_two:tcp_svc_two. */
	addr.user_ip4 = v4_svc_two;
	addr.user_port = tcp_svc_two;
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("ret: %d", ret);
	test_log("pod_one [%lx] -> svc_two [%lx]", addr.sk->src_ip4, addr.user_ip4);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == tcp_dst_one);
	assert(ret == 0);

	/* LB xlate happens when pod_two is connecting to v4_svc_one:tcp_svc_one. */
	addr.sk->src_ip4 = v4_pod_two;
	addr.user_ip4 = v4_svc_one;
	addr.user_port = tcp_svc_one;
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("ret: %d", ret);
	test_log("pod_two [%lx] -> svc_one [%lx]", addr.sk->src_ip4, addr.user_ip4);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == tcp_dst_one);
	assert(ret == 0);

	test_finish();
}

CHECK("xdp", "sock6_xlate_fwd")
int test_sock6_xlate_fwd_skip_lb(__maybe_unused struct xdp_md *ctx)
{
	int ret;
	__u16 revnat_id = 1;
	__u16 revnat_id2 = 2;
	union v6addr frontend_ip1 = {};
	union v6addr frontend_ip2 = {};

	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.user_port = tcp_svc_one,
		.protocol = IPPROTO_TCP,
		.sk = &sk,
	};
	struct skip_lb6_key key = {
		.netns_cookie = NETNS_COOKIE,
		.port = tcp_svc_one,
	};
	__u8 val = 0;

	memcpy(frontend_ip1.addr, (void *)V6_SVC_ONE, 16);
	memcpy(frontend_ip2.addr, (void *)V6_SVC_TWO, 16);
	lb_v6_add_service_with_flags(&frontend_ip1, tcp_svc_one, IPPROTO_TCP, 1, revnat_id,
				     0, SVC_FLAG_LOCALREDIRECT);
	lb_v6_add_service_with_flags(&frontend_ip2, tcp_svc_two, IPPROTO_TCP, 1, revnat_id2,
				     0, SVC_FLAG_LOCALREDIRECT);
	lb_v6_add_backend(&frontend_ip1, tcp_svc_one, 1, 124,
			  (union v6addr *)V6_BACKEND1, tcp_dst_one, IPPROTO_TCP, 0);
	lb_v6_add_backend(&frontend_ip2, tcp_svc_two, 1, 124,
			  (union v6addr *)V6_BACKEND1, tcp_dst_one, IPPROTO_TCP, 0);
	memcpy(&key.address, (void *)V6_SVC_ONE, 16);
	ret = map_update_elem(&cilium_skip_lb6, &key, &val, BPF_ANY);
	/* Needed to avoid sock6_skip_xlate */
	ipcache_v6_add_entry((union v6addr *)V6_BACKEND1, 0, 112233, 0, 0);

	test_init();

	/* Skip LB xlate when pod_one is connecting to V6_SVC_ONE:tcp_svc_one. */
	addr.sk->src_ip6[0] = bpf_htonl(0xfd040000);
	addr.sk->src_ip6[1] = 0;
	addr.sk->src_ip6[2] = 0;
	addr.sk->src_ip6[3] = bpf_htonl(1);
	memcpy(addr.user_ip6, (void *)V6_SVC_ONE, 16);
	addr.user_port = tcp_svc_one;
	ret = __sock6_xlate_fwd(&addr, false);
	test_log("ret: %d", ret);
	test_log("pod_one [%lx] -> svc_one [%lx]", addr.sk->src_ip6[0], addr.user_ip6[0]);
	assert(addr.user_ip6[0] == bpf_htonl(0xfd050000));
	assert(addr.user_ip6[1] == 0);
	assert(addr.user_ip6[2] == 0);
	assert(addr.user_ip6[3] == bpf_htonl(1));
	assert(addr.user_port == tcp_svc_one);
	assert(ret == -ENXIO);

	/* LB xlate happens when pod_one is connecting to V6_SVC_TWO:tcp_svc_two. */
	addr.sk->src_ip6[0] = bpf_htonl(0xfd040000);
	addr.sk->src_ip6[1] = 0;
	addr.sk->src_ip6[2] = 0;
	addr.sk->src_ip6[3] = bpf_htonl(1);
	memcpy(addr.user_ip6, (void *)V6_SVC_TWO, 16);
	addr.user_port = tcp_svc_two;
	ret = __sock6_xlate_fwd(&addr, false);
	test_log("ret: %d", ret);
	test_log("pod_one [%lx] -> svc_two [%lx]", addr.sk->src_ip6[0], addr.user_ip6[0]);
	assert(addr.user_ip6[0] == bpf_htonl(0xfd040000));
	assert(addr.user_ip6[1] == 0);
	assert(addr.user_ip6[2] == 0);
	assert(addr.user_ip6[3] == bpf_htonl(1));
	assert(addr.user_port == tcp_dst_one);
	assert(ret == 0);

	/* LB xlate happens when pod_two is connecting to v4_svc_one:tcp_svc_one. */
	addr.sk->src_ip6[0] = bpf_htonl(0xfd040000);
	addr.sk->src_ip6[1] = 0;
	addr.sk->src_ip6[2] = 0;
	addr.sk->src_ip6[3] = bpf_htonl(2);
	memcpy(addr.user_ip6, (void *)V6_SVC_ONE, 16);
	addr.user_port = tcp_svc_one;
	ret = __sock6_xlate_fwd(&addr, false);
	test_log("ret: %d", ret);
	test_log("pod_two [%lx] -> svc_one [%lx]", addr.sk->src_ip6[0], addr.user_ip6[0]);
	assert(addr.user_ip6[0] == bpf_htonl(0xfd040000));
	assert(addr.user_ip6[1] == 0);
	assert(addr.user_ip6[2] == 0);
	assert(addr.user_ip6[3] == bpf_htonl(1));
	assert(addr.user_port == tcp_dst_one);
	assert(ret == 0);

	test_finish();
}
