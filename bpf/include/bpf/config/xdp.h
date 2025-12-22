/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to the XDP stage (bpf_xdp.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

DECLARE_CONFIG(bool, enable_xdp_prefilter, "Enable XDP Prefilter")
