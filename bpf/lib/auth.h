/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_AUTH_H_
#define __LIB_AUTH_H_

#include "common.h"
#include "maps.h"
#include "utime.h"
#include "signal.h"

static __always_inline int
auth_lookup(struct __ctx_buff *ctx, __u32 local_id, __u32 remote_id, __u16 remote_node_id,
	    __u8 auth_type)
{
	struct auth_info *auth;
	struct auth_key key = {
		.local_sec_label = local_id,
		.remote_sec_label = remote_id,
		.remote_node_id = remote_node_id,
		.auth_type = auth_type,
		.pad = 0,
	};

	/* Check L3-proto policy */
	auth = map_lookup_elem(&AUTH_MAP, &key);
	if (likely(auth)) {
		/* check that entry has not expired */
		if (utime_get_time() < auth->expiration)
			return CTX_ACT_OK;
	}

	send_signal_auth_required(ctx, &key);
	return DROP_POLICY_AUTH_REQUIRED;
}
#endif
