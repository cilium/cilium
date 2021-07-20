/* GENERATED FROM bpf/helpers.h */
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __MOCK_HELPERS__
#define __MOCK_HELPERS__

#include <linux/bpf.h>

#include <bpf/compiler.h>





/* Map access/manipulation */
void *map_lookup_elem(const void *map, const void *key);
int map_update_elem(const void *map, const void *key,
		    const void *value, __u32 flags);
int map_delete_elem(const void *map, const void *key);

/* Time access */
__u64 ktime_get_ns();
__u64 ktime_get_boot_ns();
__u64 jiffies64();
#define jiffies	jiffies64()

/* We have cookies! ;-) */
__sock_cookie get_socket_cookie(void *ctx);
__net_cookie get_netns_cookie(void *ctx);

/* Debugging */
void
trace_printk(const char *fmt, int fmt_size, ...);

/* Random numbers */
__u32 get_prandom_u32();

/* Checksumming */
int csum_diff_external(const void *from, __u32 size_from,
			  const void *to, __u32 size_to, __u32 seed);

/* Tail calls */
void tail_call(void *ctx, const void *map, __u32 index);

/* System helpers */
__u32 get_smp_processor_id();

/* Padded struct so the dmac at the end can be passed to another helper
 * e.g. as a map value buffer. Otherwise verifier will trip over it with
 * 'invalid indirect read from stack off'.
 */
struct bpf_fib_lookup_padded {
	struct bpf_fib_lookup l;
	__u8 pad[2];
};

/* Routing helpers */
int fib_lookup(void *ctx, struct bpf_fib_lookup *params,
		    __u32 plen, __u32 flags);

/* Sockops and SK_MSG helpers */
int sock_map_update(struct bpf_sock_ops *skops, void *map,
		    __u32 key,  __u64 flags);
int sock_hash_update(struct bpf_sock_ops *skops, void *map,
		    void *key,  __u64 flags);
int msg_redirect_hash(struct sk_msg_md *md, void *map,
		    void *key, __u64 flags);

/* Socket lookup helpers */
struct bpf_sock *sk_lookup_tcp(void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);
struct bpf_sock *sk_lookup_udp(void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);

/* Socket helpers, misc */
/* Remapped name to avoid clash with getsockopt(2) when included from
 * regular applications.
 */
int get_socket_opt(void *ctx, int level, int optname,
			  void *optval, int optlen);

#endif /* __MOCK_HELPERS__ */
