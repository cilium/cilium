/* GENERATED FROM bpf/helpers_xdp.h */
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __MOCK_HELPERS_XDP__
#define __MOCK_HELPERS_XDP__

#include <linux/bpf.h>

#include <bpf/compiler.h>
#include <bpf/features_xdp.h>

/* Only used helpers in Cilium go below. */

/* Packet misc meta data & encapsulation helper */
int xdp_adjust_meta(struct xdp_md *xdp, int delta);
int xdp_adjust_head(struct xdp_md *xdp, int delta);
int xdp_adjust_tail(struct xdp_md *xdp, int delta);

/* Packet redirection */
int redirect(int ifindex, __u32 flags);

/* Packet manipulation */
int xdp_load_bytes(struct xdp_md *xdp, __u32 off,
		    void *to, __u32 len);
int xdp_store_bytes(struct xdp_md *xdp, __u32 off,
		    const void *from, __u32 len, __u32 flags);

int l3_csum_replace(struct xdp_md *xdp, __u32 off,
		    __u32 from, __u32 to, __u32 flags);
int l4_csum_replace(struct xdp_md *xdp, __u32 off,
		    __u32 from, __u32 to, __u32 flags);

int xdp_adjust_room(struct xdp_md *xdp, __s32 len_diff,
		    __u32 mode, __u64 flags);

int xdp_change_type(struct xdp_md *xdp, __u32 type);
int xdp_change_proto(struct xdp_md *xdp, __u32 proto,
		    __u32 flags);
int xdp_change_tail(struct xdp_md *xdp, __u32 nlen,
		    __u32 flags);

/* Packet tunnel encap/decap */
int xdp_get_tunnel_key(struct xdp_md *xdp,
		    struct bpf_tunnel_key *to, __u32 size, __u32 flags);
int xdp_set_tunnel_key(struct xdp_md *xdp,
		    const struct bpf_tunnel_key *from, __u32 size,
		    __u32 flags);

/* Events for user space */
int xdp_event_output(struct xdp_md *xdp, void *map,
			  __u64 index, const void *data, __u32 size);

#endif /* __MOCK_HELPERS_XDP__ */
