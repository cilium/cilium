/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to WireGuard device (bpf_wireguard.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>
DECLARE_CONFIG(__u32, wireguard_secctx_from_ipcache, "Pull security context from IP cache")
#define SECCTX_FROM_IPCACHE CONFIG(wireguard_secctx_from_ipcache) /* Backwards compatibility */
