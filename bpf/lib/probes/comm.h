/*
 *  Copyright (C) 2018 Authors of Cilium
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

#ifndef __LIB_PROBES_COMM_H_
#define __LIB_PROBES_COMM_H_

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

union comm {
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	char comm[TASK_COMM_LEN];
};

struct comm_event {
	u32		pid;
	union comm	comm;
};

BPF_HASH(pid2comm_map, u32, struct comm_event);

static inline void copy_comm(union comm *src, union comm *dst)
{
	dst->p1 = src->p1;
	dst->p2 = src->p2;
	dst->p3 = src->p3;
	dst->p4 = src->p4;
}

#endif /* __LIB_PROBES_COMM_H_ */
