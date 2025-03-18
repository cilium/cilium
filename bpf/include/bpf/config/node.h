/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file contains node-level configuration data, available to all bpf_*.c
 * objects.
 *
 * See https://docs.cilium.io/en/latest/contributing/development/datapath_config
 * for guidelines and recommendations.
 */

#pragma once

#include <lib/static_data.h>

/* Legacy node config rendered at agent runtime. */
#include <node_config.h>
