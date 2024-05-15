/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/if_ether.h>
#include <linux/byteorder.h>

#define __section_entry	__section("xdp")

#define __ctx_buff			xdp_md
#define __ctx_is			__ctx_xdp

#include "common.h"
#include "../helpers_xdp.h"
#include "../builtins.h"
#include "../section.h"
#include "../loader.h"
#include "../csum.h"

#define CTX_ACT_OK			XDP_PASS
#define CTX_ACT_DROP			XDP_DROP
#define CTX_ACT_TX			XDP_TX	/* hairpin only */
#define CTX_ACT_REDIRECT		XDP_REDIRECT

#define CTX_DIRECT_WRITE_OK		1

					/* cb + RECIRC_MARKER + XFER_MARKER */
#define META_PIVOT			((int)(field_sizeof(struct __sk_buff, cb) + \
					       sizeof(__u32) * 2))

/* This must be a mask and all offsets guaranteed to be less than that. */
#define __CTX_OFF_MAX			0xff

#ifndef HAVE_XDP_LOAD_BYTES
static __always_inline __maybe_unused int
xdp_load_bytes(const struct xdp_md *ctx, __u64 off, void *to, const __u64 len)
{
	void *from;
	int ret;
	/* LLVM tends to generate code that verifier doesn't understand,
	 * so force it the way we want it in order to open up a range
	 * on the reg.
	 */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[from] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [from]"=r"(from)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}
#endif

#ifndef HAVE_XDP_STORE_BYTES
static __always_inline __maybe_unused int
xdp_store_bytes(const struct xdp_md *ctx, __u64 off, const void *from,
		const __u64 len, __u64 flags __maybe_unused)
{
	void *to;
	int ret;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[to] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [to]"=r"(to)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}
#endif

#define ctx_load_bytes			xdp_load_bytes
#define ctx_store_bytes			xdp_store_bytes

/* Fyi, remapping to stubs helps to assert that the code is not in
 * use since it otherwise triggers a verifier error.
 */

#define ctx_change_type			xdp_change_type__stub
#define ctx_change_tail			xdp_change_tail__stub

#define ctx_pull_data(ctx, ...)		do { /* Already linear. */ } while (0)

#define ctx_get_tunnel_key		xdp_get_tunnel_key__stub
#define ctx_set_tunnel_key		xdp_set_tunnel_key__stub

#define ctx_get_tunnel_opt		xdp_get_tunnel_opt__stub

#define ctx_event_output		xdp_event_output

#define ctx_adjust_meta			xdp_adjust_meta

#define get_hash(ctx)			({ 0; })
#define get_hash_recalc(ctx)		get_hash(ctx)

#define DEFINE_FUNC_CTX_POINTER(FIELD)						\
static __always_inline void *							\
ctx_ ## FIELD(const struct xdp_md *ctx)						\
{										\
	void *ptr;								\
										\
	/* LLVM may generate u32 assignments of ctx->{data,data_end,data_meta}.	\
	 * With this inline asm, LLVM loses track of the fact this field is on	\
	 * 32 bits.								\
	 */									\
	asm volatile("%0 = *(u32 *)(%1 + %2)"					\
		     : "=r"(ptr)						\
		     : "r"(ctx), "i"(offsetof(struct xdp_md, FIELD)));		\
	return ptr;								\
}
/* This defines ctx_data(). */
DEFINE_FUNC_CTX_POINTER(data)
/* This defines ctx_data_end(). */
DEFINE_FUNC_CTX_POINTER(data_end)
/* This defines ctx_data_meta(). */
DEFINE_FUNC_CTX_POINTER(data_meta)
#undef DEFINE_FUNC_CTX_POINTER

static __always_inline __maybe_unused void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static __always_inline __maybe_unused void
__csum_replace_by_4(__sum16 *sum, __wsum from, __wsum to)
{
	__csum_replace_by_diff(sum, csum_add(~from, to));
}

static __always_inline __maybe_unused int
l3_csum_replace(struct xdp_md *ctx, __u64 off, const __u32 from,
		__u32 to,
		__u32 flags)
{
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 sum;
	int ret = 0;

	if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	ret = xdp_load_bytes(ctx, off, &sum, 2);

	if (!ret)
		from ? __csum_replace_by_4(&sum, from, to) :
		       __csum_replace_by_diff(&sum, to);
	return ret;
}

#define CSUM_MANGLED_0		((__sum16)0xffff)

static __always_inline __maybe_unused int
l4_csum_replace(struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	ret = xdp_load_bytes(ctx, off, &sum, 2);

	if (!ret) {
		if (is_mmzero && !sum)
			return 0;
		from ? __csum_replace_by_4(&sum, from, to) :
		       __csum_replace_by_diff(&sum, to);
		if (is_mmzero && !sum)
			sum = CSUM_MANGLED_0;
	}
	return ret;
}

static __always_inline __maybe_unused int
ctx_change_proto(struct xdp_md *ctx __maybe_unused,
		 const __be16 proto __maybe_unused,
		 const __u64 flags __maybe_unused)
{
	const __s32 len_diff = proto == __constant_htons(ETH_P_IPV6) ?
			       20 /* 4->6 */ : -20 /* 6->4 */;
	const __u32 move_len = 14;
	void *data, *data_end;
	int ret;

	/* We make the assumption that when ctx_change_proto() is called
	 * the target proto != current proto.
	 */
	build_bug_on(flags != 0);
	build_bug_on(proto != __constant_htons(ETH_P_IPV6) &&
		     proto != __constant_htons(ETH_P_IP));

	if (len_diff < 0) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		if (data + move_len + -len_diff <= data_end)
			__bpf_memmove_fwd(data + -len_diff, data, move_len);
		else
			return -EFAULT;
	}
	ret = xdp_adjust_head(ctx, -len_diff);
	if (!ret && len_diff > 0) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		if (data + move_len + len_diff <= data_end)
			__bpf_memmove_fwd(data, data + len_diff, move_len);
		else
			return -EFAULT;
	}
	return ret;
}

static __always_inline __maybe_unused int
ctx_adjust_troom(struct xdp_md *ctx, const __s32 len_diff)
{
	return xdp_adjust_tail(ctx, len_diff);
}

static __always_inline __maybe_unused int
ctx_adjust_hroom(struct xdp_md *ctx, const __s32 len_diff, const __u32 mode,
		 const __u64 flags __maybe_unused)
{
	const __u32 move_len_v4_geneve = 14 + 20 + 8 + 8; /* eth, ipv4, udp, geneve */
	const __u32 move_len_v4 = 14 + 20;
	const __u32 move_len_v6 = 14 + 40;
	int ret;

	/* Note: when bumping len_diff, consider headroom on popular NICs. */
	build_bug_on(len_diff <= 0 || len_diff >= 128);
	build_bug_on(mode != BPF_ADJ_ROOM_NET);

	ret = xdp_adjust_head(ctx, -len_diff);

	/* XXX: Note, this hack is currently tailored to NodePort DSR
	 * requirements and not a generic helper. If needed elsewhere,
	 * this must be made more generic.
	 */
	if (!ret) {
		__u32 move_len = 0;

		/* Based on the specified `len_diff`, we now *guess* at what
		 * location the free space is needed.
		 *
		 * We either want to push some additional headers to the front
		 * (move_len == 0), or insert headers at an offset (move_len > 0).
		 */

		switch (len_diff) {
		case 28: /* struct {iphdr + icmphdr} */
			break;
		case 12: /* struct geneve_dsr_opt4 */
			move_len = move_len_v4_geneve;
			break;
		case 20: /* struct iphdr */
		case 8:  /* struct dsr_opt_v4 */
			move_len = move_len_v4;
			break;
		case 50: /* struct {ethhdr + iphdr + udphdr + genevehdr / vxlanhdr} */
		case 50 + 12: /* geneve with IPv4 DSR option */
		case 50 + 24: /* geneve with IPv6 DSR option */
			break;
		case 48: /* struct {ipv6hdr + icmp6hdr} */
			break;
		case 40: /* struct ipv6hdr */
		case 24: /* struct dsr_opt_v6 */
			move_len = move_len_v6;
			break;
		default:
			__throw_build_bug();
		}

		/* Move existing headers to the front, to create space for
		 * inserting additional headers.
		 */
		if (move_len) {
			void *data_end = ctx_data_end(ctx);
			void *data = ctx_data(ctx);

			if (data + len_diff + move_len <= data_end)
				__bpf_memmove_fwd(data, data + len_diff, move_len);
			else
				ret = -EFAULT;
		}
	}

	return ret;
}

static __always_inline __maybe_unused int
ctx_redirect(const struct xdp_md *ctx, int ifindex, const __u32 flags)
{
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;

	return redirect(ifindex, flags);
}

static __always_inline __maybe_unused int
ctx_redirect_peer(const struct xdp_md *ctx __maybe_unused,
		  int ifindex __maybe_unused,
		  const __u32 flags __maybe_unused)
{
	/* bpf_redirect_peer() is available only in TC BPF. */
	return -ENOTSUP;
}

#ifdef HAVE_XDP_GET_BUFF_LEN
static __always_inline __maybe_unused __u64
ctx_full_len(const struct xdp_md *ctx)
{
	return xdp_get_buff_len((struct xdp_md *)ctx);
}
#else
static __always_inline __maybe_unused __u64
ctx_full_len(const struct xdp_md *ctx)
{
	__u64 len;
	/* Compute the length using inline assembly as clang
	 * sometimes reorganizes expressions involving this,
	 * which leads to "pointer arithmetic on pkt_end prohibited"
	 */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[len] = r2\n\t"
		     "%[len] -= r1\n\t"
		     : [len]"=r"(len)
		     : [ctx]"r"(ctx)
		     : "r1", "r2");
	return len;
}
#endif

static __always_inline __maybe_unused __u32
ctx_wire_len(const struct xdp_md *ctx)
{
	return ctx_full_len(ctx);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, META_PIVOT);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} cilium_xdp_scratch __section_maps_btf;

static __always_inline __maybe_unused void
ctx_store_meta(struct xdp_md *ctx __maybe_unused, const __u64 off, __u32 datum)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		data_meta[off] = datum;
	build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
}

static __always_inline __maybe_unused __u32
ctx_load_meta(const struct xdp_md *ctx __maybe_unused, const __u64 off)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		return data_meta[off];
	build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
	return 0;
}

static __always_inline __maybe_unused __u32
ctx_load_and_clear_meta(const struct xdp_md *ctx __maybe_unused, const __u64 off)
{
	__u32 val, zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta)) {
		val = data_meta[off];
		data_meta[off] = 0;
		return val;
	}

	build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
	return 0;
}

static __always_inline __maybe_unused __u16
ctx_get_protocol(const struct xdp_md *ctx)
{
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = ctx_data(ctx);

	if (ctx_no_room(eth + 1, data_end))
		return 0;

	return eth->h_proto;
}

static __always_inline __maybe_unused __u32
ctx_get_ifindex(const struct xdp_md *ctx)
{
	return ctx->ingress_ifindex;
}

static __always_inline __maybe_unused __u32
ctx_get_ingress_ifindex(const struct xdp_md *ctx)
{
	return ctx->ingress_ifindex;
}
