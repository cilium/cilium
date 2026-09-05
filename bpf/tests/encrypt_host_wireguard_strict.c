// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_WIREGUARD	1

#include "encrypt_host.h"

ASSIGN_CONFIG(struct strict_encryption_cfg, strict_egress_encryption, {
	.enabled = true,
	.ipv4_net = { .be32 = IPV4(192, 168, 0, 0) },
	.ipv4_net_size = 16,
});
