/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_CTX_XDP_H_
#define __BPF_CTX_XDP_H_

#include <linux/if_ether.h>

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

#define CTX_DIRECT_WRITE_OK		1

					/* cb + RECIRC_MARKER + XFER_MARKER */
#define META_PIVOT			((int)(field_sizeof(struct __sk_buff, cb) + \
					       sizeof(__u32) * 2))

/* This must be a mask and all offsets guaranteed to be less than that. */
#define __CTX_OFF_MAX			0xff

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

#define ctx_load_bytes			xdp_load_bytes
#define ctx_store_bytes			xdp_store_bytes

/* Fyi, remapping to stubs helps to assert that the code is not in
 * use since it otherwise triggers a verifier error.
 */

#define ctx_change_type			xdp_change_type__stub
#define ctx_change_proto		xdp_change_proto__stub
#define ctx_change_tail			xdp_change_tail__stub

#define ctx_pull_data(ctx, ...)		do { /* Already linear. */ } while (0)

#define ctx_get_tunnel_key		xdp_get_tunnel_key__stub
#define ctx_set_tunnel_key		xdp_set_tunnel_key__stub

#define ctx_event_output		xdp_event_output

#define ctx_adjust_meta			xdp_adjust_meta

#define get_hash(ctx)			({ 0; })
#define get_hash_recalc(ctx)		get_hash(ctx)

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
l3_csum_replace(const struct xdp_md *ctx, __u64 off, const __u32 from,
		__u32 to,
		__u32 flags)
{
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
	return ret;
}

#define CSUM_MANGLED_0		((__sum16)0xffff)

static __always_inline __maybe_unused int
l4_csum_replace(const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret) {
		if (is_mmzero && !*sum)
			return 0;
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
		if (is_mmzero && !*sum)
			*sum = CSUM_MANGLED_0;
	}
	return ret;
}

static __always_inline __maybe_unused int
ctx_adjust_room(struct xdp_md *ctx, const __s32 len_diff, const __u32 mode,
		const __u64 flags __maybe_unused)
{
	const __u32 move_len_v4 = 14 + 20;
	const __u32 move_len_v6 = 14 + 40;
	void *data, *data_end;
	int ret;

	build_bug_on(len_diff <= 0 || len_diff >= 64);
	build_bug_on(mode != BPF_ADJ_ROOM_NET);

	ret = xdp_adjust_head(ctx, -len_diff);

	/* XXX: Note, this hack is currently tailored to NodePort DSR
	 * requirements and not a generic helper. If needed elsewhere,
	 * this must be made more generic.
	 */
	if (!ret) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		switch (len_diff) {
		case 20: /* struct iphdr */
		case 8:  /* __u32 opt[2] */
			if (data + move_len_v4 + len_diff <= data_end)
				__bpf_memmove_fwd(data, data + len_diff,
						  move_len_v4);
			else
				ret = -EFAULT;
			break;
		case 40: /* struct ipv6hdr */
		case 24: /* struct dsr_opt_v6 */
			if (data + move_len_v6 + len_diff <= data_end)
				__bpf_memmove_fwd(data, data + len_diff,
						  move_len_v6);
			else
				ret = -EFAULT;
			break;
		default:
			__throw_build_bug();
		}
	}
	return ret;
}

#define redirect			redirect__stub
#define redirect_peer			redirect

static __always_inline __maybe_unused int
ctx_redirect(const struct xdp_md *ctx, int ifindex, const __u32 flags)
{
	if (unlikely(flags))
		return -ENOTSUPP;
	if ((__u32)ifindex != ctx->ingress_ifindex)
		return -ENOTSUPP;
	return XDP_TX;
}

static __always_inline __maybe_unused __u32
ctx_full_len(const struct xdp_md *ctx)
{
	/* No non-linear section in XDP. */
	return ctx_data_end(ctx) - ctx_data(ctx);
}

static __always_inline __maybe_unused __u32
ctx_wire_len(const struct xdp_md *ctx)
{
	return ctx_full_len(ctx);
}

struct bpf_elf_map __section_maps cilium_xdp_scratch = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= META_PIVOT,
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

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

#endif /* __BPF_CTX_XDP_H_ */
