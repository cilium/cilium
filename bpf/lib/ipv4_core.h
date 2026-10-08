/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

union v4addr {
	__u8 addr[4];
	__be32 be32;
};
