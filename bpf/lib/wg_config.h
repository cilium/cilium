/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

DECLARE_CONFIG(__u32, wg_ifindex, "Index of the WireGuard interface.")
DECLARE_CONFIG(__u16, wg_port, "Port for the WireGuard interface.")
