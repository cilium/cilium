/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to socketLB (bpf_sock.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

DECLARE_CONFIG(bool, enable_no_service_endpoints_routable,
	       "Enable routes when service has 0 endpoints")
