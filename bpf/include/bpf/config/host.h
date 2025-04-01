/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to workload endpoints (bpf_host.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

#include <linux/if_ether.h>
/* Allow ETH_HLEN to be overridden from tests. Careful, lib/eth.h contains
 * another ifndef-guarded definition, so the one here needs to go first.
 */
#ifndef ETH_HLEN
/* Make the ethernet header length configurable only on bpf_host since it can be
 * attached to different kinds of interfaces, like external devices, cilium_host
 * and cilium_net. Other programs have this value hardcoded, but here it can be
 * set to 0 from user space if attached to an L2-less external device.
 */
DECLARE_CONFIG(__u8, eth_header_length, "Length of the Ethernet header on this device. May be set to zero on L2-less devices. (default __ETH_HLEN)")
ASSIGN_CONFIG(__u8, eth_header_length, __ETH_HLEN)
#define ETH_HLEN CONFIG(eth_header_length)
#endif
