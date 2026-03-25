#pragma once

#include "common.h"

#ifndef POLICY_VERDICT_EXTENSION
#define POLICY_VERDICT_EXTENSION
#define policy_verdict_extension_hook(ctx, msg) do {} while (0)
#endif

struct policy_verdict_notify {
	NOTIFY_CAPTURE_HDR
	__u32	remote_label;
	__s32	verdict;
	__u16	dst_port;
	__u8	proto;
	__u8	dir:2,
		ipv6:1,
		match_type:3,
		audited:1,
		l3:1;
	__u8	auth_type;
	__u8	pad1[3]; /* align with 64 bits */
	__u32	cookie;
	__u32	pad2; /* align with 64 bits */
	POLICY_VERDICT_EXTENSION
};
