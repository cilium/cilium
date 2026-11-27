/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "tc_lxc_proxy_delegation.h"

/* SCTP keeps per-packet LB enabled with full Socket LB. Delegated TCP must
 * still skip backend selection.
 */
ASSIGN_CONFIG(struct socket_lb_config, socket_lb, { .enable_full = true })
ASSIGN_CONFIG(bool, enable_sctp, true)
