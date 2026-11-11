// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Per-endpoint routes without the MARK_MAGIC_PROXY_EGRESS_EPID ip rule in
 * place yet, eg. while upgrading from a version that did not install it: the
 * per-endpoint route steers L7 LB traffic to the backend's lxc device, and the
 * egress policy program is tail called from cil_to_container.
 */

#define PER_ENDPOINT_ROUTES	1
#define FROM_CIL_TO_CONTAINER	1

#include "l7_lb_local_backend.h"
