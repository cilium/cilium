/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__be32 addr;
};

struct lpm_v6_key {
	struct bpf_lpm_trie_key lpm;
	struct in6_addr addr;
};

struct lpm_val {
	/* Just dummy for now. */
	__u8 flags;
};
