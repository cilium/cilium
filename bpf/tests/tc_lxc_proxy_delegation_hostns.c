/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "tc_lxc_proxy_delegation.h"

ASSIGN_CONFIG(struct socket_lb_config, socket_lb, { .hostns_only = true })
