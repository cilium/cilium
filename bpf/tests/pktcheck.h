/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include <bpf/builtins.h>
#include <bpf/helpers.h>

#include <lib/endian.h>

#include <linux/byteorder.h>
#include <linux/ip.h>
#include <linux/in.h>

static __always_inline
int pktcheck__validate_ipv4(struct iphdr *ip4, __u8 nexthdr, __be32 saddr, __be32 daddr)
{
	if (ip4->protocol != nexthdr)
		return -1;
	if (ip4->saddr != saddr)
		return -1;
	if (ip4->daddr != daddr)
		return -1;

	/* Skip csum validation if options are present */
	if (ip4->ihl * 4 == sizeof(*ip4)) {
		if (csum_fold(csum_diff(NULL, 0, ip4, sizeof(*ip4), 0)))
			return -1;
	}

	return 0;
}
