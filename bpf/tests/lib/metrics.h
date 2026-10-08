/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline void
metrics_del_entry(__u8 reason, enum metric_dir dir)
{
	struct metrics_key key = {
		.reason = reason,
		.dir = dir,
	};

	map_delete_elem(&cilium_metrics, &key);
}
