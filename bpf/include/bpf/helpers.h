/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

#include <linux/bpf.h>

#include "ctx/ctx.h"
#include "compiler.h"

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused = (void *)BPF_FUNC_##NAME
#endif

#ifndef BPF_STUB
# define BPF_STUB(NAME, ...)						\
	(* NAME##__stub)(__VA_ARGS__) __maybe_unused = (void *)((__u32)-1)
#endif

#ifndef BPF_FUNC_REMAP
# define BPF_FUNC_REMAP(NAME, ...)					\
	(* NAME)(__VA_ARGS__) __maybe_unused
#endif

#if __ctx_is == __ctx_skb
# include "helpers_skb.h"
#else
# include "helpers_xdp.h"
#endif

/* Map access/manipulation */
static void *BPF_FUNC(map_lookup_elem, const void *map, const void *key);
static int BPF_FUNC(map_update_elem, const void *map, const void *key,
		    const void *value, __u32 flags);
static int BPF_FUNC(map_delete_elem, const void *map, const void *key);
static void *BPF_FUNC(map_lookup_percpu_elem, void *map, const void *key,
				unsigned int cpu);

/* Time access */
static __u64 BPF_FUNC(ktime_get_ns);
static __u64 BPF_FUNC(ktime_get_boot_ns);
static __u64 BPF_FUNC(jiffies64);
#define jiffies	jiffies64()

/* We have cookies! ;-) */
static __sock_cookie BPF_FUNC(get_socket_cookie, void *ctx);
static __net_cookie BPF_FUNC(get_netns_cookie, void *ctx);

/* Legacy cgroups */
static __u32 BPF_FUNC(get_cgroup_classid);

/* Debugging */
static __printf(1, 3) void
BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

/* Random numbers */
static __u32 BPF_FUNC(get_prandom_u32);

/* Checksumming */
static int BPF_FUNC_REMAP(csum_diff_external, const void *from, __u32 size_from,
			  const void *to, __u32 size_to, __u32 seed) =
	(void *)BPF_FUNC_csum_diff;

/* Tail calls */
static void BPF_FUNC(tail_call, void *ctx, const void *map, __u32 index);

/* System helpers */
static __u32 BPF_FUNC(get_smp_processor_id);

/* Padded struct so the dmac at the end can be passed to another helper
 * e.g. as a map value buffer. Otherwise verifier will trip over it with
 * 'invalid indirect read from stack off'.
 */
struct bpf_fib_lookup_padded {
	struct bpf_fib_lookup l;
	__u8 pad[2];
};

/* Routing helpers */
static int BPF_FUNC(fib_lookup, void *ctx, struct bpf_fib_lookup *params,
		    __u32 plen, __u32 flags);

/* Socket lookup helpers */
static struct bpf_sock *BPF_FUNC(sk_lookup_tcp, void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);
static struct bpf_sock *BPF_FUNC(sk_lookup_udp, void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);

/* Socket helpers, misc */
/* Remapped name to avoid clash with getsockopt(2) when included from
 * regular applications.
 */
static int BPF_FUNC_REMAP(get_socket_opt, void *ctx, int level, int optname,
			  void *optval, int optlen) =
	(void *)BPF_FUNC_getsockopt;

static __u64 BPF_FUNC(get_current_cgroup_id);

static int BPF_FUNC(set_retval, int retval);

static inline int try_set_retval(int retval __maybe_unused)
{
#ifdef HAVE_SET_RETVAL
	return set_retval(retval);
#else
	return 0;
#endif
}

#endif /* __BPF_HELPERS__ */
