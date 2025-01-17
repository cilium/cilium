/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration is available to bpf programs representing an Endpoint
 * within the Cilium agent, like host endpoints (bpf_host.c) and workload
 * endpoints (bpf_lxc.c).
 */

#pragma once

#include <lib/static_data.h>

/* Legacy endpoint config rendered at agent runtime. */
#include <ep_config.h>

DECLARE_CONFIG(__u32, security_label, "The endpoint's security label")
#define SECLABEL CONFIG(security_label) /* Backwards compatibility */
/* All security labels are identical for workload endpoints. */
#define SECLABEL_IPV4 SECLABEL
#define SECLABEL_IPV6 SECLABEL
