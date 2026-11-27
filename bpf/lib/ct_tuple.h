/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/types.h>
#include <bpf/compiler.h>

#include "ipv6_core.h"

struct ipv6_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	union v6addr	daddr;
	union v6addr	saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;
