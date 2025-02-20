/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#if !defined(__LIB_ICMP4__) && defined(ENABLE_IPV4)
#define __LIB_ICMP4__

#include <linux/icmp.h>
#include <linux/in.h>
#include "common.h"
#include "eth.h"
#include "drop.h"
#include "eps.h"
#include "ipv4.h"

#define ICMP4_TYPE_OFFSET offsetof(struct icmphdr, type)
#define ICMP4_CSUM_OFFSET (sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))

static __always_inline int icmp4_load_type(struct __ctx_buff *ctx, int l4_off, __u8 *type)
{
    return ctx_load_bytes(ctx, l4_off + ICMP4_TYPE_OFFSET, type, sizeof(*type));
}

static __always_inline int icmp4_send_reply(struct __ctx_buff *ctx, int nh_off)
{
    union macaddr smac, dmac = THIS_INTERFACE_MAC;
    const int csum_off = nh_off + ICMP4_CSUM_OFFSET;
    __be32 sum, sip, dip, router_ip;

    if (ctx_load_bytes(ctx, nh_off + offsetof(struct iphdr, saddr), &sip, 4) < 0 ||
        ctx_load_bytes(ctx, nh_off + offsetof(struct iphdr, daddr), &dip, 4) < 0)
        return DROP_INVALID;

    router_ip = IPV4_GATEWAY;
    /* ctx->saddr = router_ip */
    if (ctx_store_bytes(ctx, nh_off + offsetof(struct iphdr, saddr), &router_ip, 4, 0) < 0)
        return DROP_WRITE_ERROR;
    /* ctx->daddr = ctx->saddr */
    if (ctx_store_bytes(ctx, nh_off + offsetof(struct iphdr, daddr), &sip, 4, 0) < 0)
        return DROP_WRITE_ERROR;

    /* fixup checksums */
    sum = csum_diff(&sip, 4, &router_ip, 4, 0);
    if (l3_csum_replace(ctx, nh_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
        return DROP_CSUM_L3;

    sum = csum_diff(&dip, 4, &sip, 4, 0);
    if (l3_csum_replace(ctx, nh_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
        return DROP_CSUM_L3;

    /* Also fixup the ICMP checksum */
    sum = csum_diff(&dip, 4, &sip, 4, 0);
    if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
        return DROP_CSUM_L4;

    sum = csum_diff(&sip, 4, &router_ip, 4, 0);
    if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
        return DROP_CSUM_L4;

    /* dmac = smac, smac = dmac */
    if (eth_load_saddr(ctx, smac.addr, 0) < 0)
        return DROP_INVALID;

    if (eth_store_daddr(ctx, smac.addr, 0) < 0 ||
        eth_store_saddr(ctx, dmac.addr, 0) < 0)
        return DROP_WRITE_ERROR;

    cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, ctx_get_ifindex(ctx));

    return redirect_self(ctx);
}

#endif
