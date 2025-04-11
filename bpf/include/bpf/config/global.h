/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration is available to all of Cilium's bpf programs. If you're
 * working on a feature, _do not_ put your new config here. Look into the other
 * config files in this directory instead.
 */

#pragma once

#include <lib/static_data.h>

DECLARE_CONFIG(union macaddr, interface_mac, "MAC address of the interface the bpf program is attached to")
#define THIS_INTERFACE_MAC CONFIG(interface_mac) /* Backwards compatibility */

DECLARE_CONFIG(__u32, interface_ifindex, "ifindex of the interface the bpf program is attached to")
#define THIS_INTERFACE_IFINDEX CONFIG(interface_ifindex) /* Backwards compatibility */

DECLARE_CONFIG(bool, secctx_from_ipcache, "Pull security context from IP cache")
