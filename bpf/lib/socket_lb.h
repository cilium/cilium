/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Note: enable_full and hostns_only are mutually exclusive. */
struct socket_lb_config {
	/* Enable full socketlb. */
	bool enable_full;
	/* Only run the socketlb in the host network namespace. */
	bool hostns_only;
	/* Enable tracing. */
	bool enable_tracing;
};

DECLARE_CONFIG(struct socket_lb_config, socket_lb, "Socket-based LB for E/W traffic")
