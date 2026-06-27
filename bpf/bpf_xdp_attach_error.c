// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#define XDP_ATTACH_ERROR_LEN 256

struct xdp_attach_error {
	__u8 msg[XDP_ATTACH_ERROR_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct xdp_attach_error);
	__uint(max_entries, 1);
} cilium_xdp_attach_err __section_maps_btf;

static long BPF_FUNC(probe_read_kernel_str, void *dst, __u32 size,
		     const void *unsafe_ptr);

/* bpf_xdp_link_attach_failed(const char *msg) - args[0] is the extack message. */
__section("raw_tp/bpf_xdp_link_attach_failed")
int xdp_attach_failed(struct bpf_raw_tracepoint_args *ctx)
{
	struct xdp_attach_error *err;
	__u32 key = 0;

	err = map_lookup_elem(&cilium_xdp_attach_err, &key);
	if (!err)
		return 0;

	probe_read_kernel_str(&err->msg, sizeof(err->msg),
			      (const void *)ctx->args[0]);
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
