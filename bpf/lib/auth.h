/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "signal.h"
#include "node.h"

static __always_inline int
auth_lookup(const struct __ctx_buff *ctx, __u32 local_id, __u32 remote_id, __u32 remote_node_ip,
	    __u8 auth_type)
{
	const struct node_value *node_value = NULL;
	struct auth_key key = {
		.local_sec_label = local_id,
		.remote_sec_label = remote_id,
		.auth_type = auth_type,
		.pad = 0,
	};

	if (remote_node_ip) {
		node_value = lookup_ip4_node(remote_node_ip);
		if (!node_value || !node_value->id)
			return DROP_NO_NODE_ID;
		key.remote_node_id = node_value->id;
	} else {
		/* If remote_node_ip is 0.0.0.0, then this is the local node. */
		key.remote_node_id = 0;
	}

	send_signal_auth_required(ctx, &key);
	return DROP_POLICY_AUTH_REQUIRED;
}
