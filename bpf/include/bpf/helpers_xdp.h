/*
 *  Copyright (C) 2016-2020 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __BPF_HELPERS_XDP__
#define __BPF_HELPERS_XDP__

#include <linux/bpf.h>

#include "compiler.h"
#include "helpers.h"

/* Events for user space */
static int BPF_FUNC_REMAP(xdp_event_output, struct xdp_md *xdp, void *map,
			  __u64 index, const void *data, __u32 size) =
			 (void *)BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_XDP__ */
