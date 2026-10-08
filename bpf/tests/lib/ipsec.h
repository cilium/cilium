/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
ipsec_set_encrypt_state(__u8 spi)
{
	struct encrypt_config cfg = {
		.encrypt_key = spi,
	};
	__u32 key = 0;

	map_update_elem(&cilium_encrypt_state, &key, &cfg, BPF_ANY);
}
