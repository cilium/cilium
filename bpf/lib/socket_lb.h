/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

DECLARE_CONFIG(bool, enable_socket_lb_hostns_only,
	       "Skip socket LB for svcs when inside pod ns, in favor of svc LB at the pod iface")
