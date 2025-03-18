/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file contains node-level configuration data, available to all bpf_*.c
 * objects. Its Go configuration scaffolding is rendered as 'struct Node' into
 * pkg/datapath/config/node_config.go and embedded into all other config
 * structs.
 *
 * Node-level configuration variables are declared using the NODE_CONFIG macro
 * and accessed using the CONFIG() macro. For example, to declare a __u32 foo:
 *
 *  NODE_CONFIG(__u32, foo, "Description of foo")
 *
 * To access it:
 *
 *  CONFIG(foo)
 *
 * Backwards compatibility macros can be declared when porting over existing
 * variables to avoid churn in existing code. This pattern is heavily
 * discouraged for new code, as it gives the false impression that the value is
 * provided at compile time:
 *
 *  #define FOO CONFIG(foo)
 */

#pragma once

#include <lib/static_data.h>

/* Legacy node config rendered at agent runtime. */
#include <node_config.h>
