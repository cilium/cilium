/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

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

/* Time access */
static __u64 BPF_FUNC(ktime_get_ns);

/* We have cookies! ;-) */
static __u64 BPF_FUNC(get_socket_cookie, void *ctx);
static __u64 BPF_FUNC(get_netns_cookie, void *ctx);

/* Debugging */
static __printf(1,3) void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef printt
# define printt(fmt, ...)						\
	({								\
		trace_printk(____fmt, ##__VA_ARGS__);			\
	})
#endif

/* Random numbers */
static __u32 BPF_FUNC(get_prandom_u32);

/* Checksumming */
static int BPF_FUNC(csum_diff, const void *from, __u32 from_size, void *to,
		    __u32 to_size, __u32 seed);

/* Tail calls */
static void BPF_FUNC(tail_call, void *ctx, void *map, __u32 index);

/* System helpers */
static __u32 BPF_FUNC(get_smp_processor_id);

/* Routing helpers */
static int BPF_FUNC(fib_lookup, void *ctx, struct bpf_fib_lookup *params,
		    __u32 plen, __u32 flags);

/* Sockops and SK_MSG helpers */
static int BPF_FUNC(sock_map_update, struct bpf_sock_ops *skops, void *map,
		    __u32 key,  __u64 flags);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops, void *map,
		    void *key,  __u64 flags);
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md, void *map,
		    void *key, __u64 flags);

#endif /* __BPF_HELPERS__ */
