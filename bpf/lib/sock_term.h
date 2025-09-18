/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

struct sock_term_filter {
	union {
		union v6addr addr6;
		struct {
			char pad[12];
			__be32 addr4;
		};
	} address __packed;
	__be16 port;
	__u8 address_family;
};

