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

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include "lib/probes/comm.h"

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(connect_events);

/* Compare with pkg/probes/api/type.go */
enum {
	TYPE_NOT_FOUND,
	TYPE_ENTER,
	TYPE_RETURN,
};

struct connect_event {
	u32 pid;
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 type;
	union comm comm;
};

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);

	struct connect_event event = {
		.pid = pid,
		.dport = sk->__sk_common.skc_dport,
		.saddr = sk->__sk_common.skc_rcv_saddr,
		.daddr = sk->__sk_common.skc_daddr,
		.type = TYPE_ENTER,
	};

	struct comm_event *comm;
	comm = pid2comm_map.lookup(&pid);
	if (comm != NULL) {
		copy_comm(&comm->comm, &event.comm);
	}

	connect_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;

	struct connect_event event = {
		.pid = pid,
		.type = TYPE_NOT_FOUND,
	};

	skpp = currsock.lookup(&pid);
	if (skpp != NULL) {
		struct sock *sk = *skpp;

		event.dport = sk->__sk_common.skc_dport;
		event.saddr = sk->__sk_common.skc_rcv_saddr;
		event.daddr = sk->__sk_common.skc_daddr;
		event.type = TYPE_RETURN;

		struct comm_event *comm;
		comm = pid2comm_map.lookup(&pid);
		if (comm != NULL) {
			copy_comm(&comm->comm, &event.comm);
		}
	}

	connect_events.perf_submit(ctx, &event, sizeof(event));

skip:
	currsock.delete(&pid);

	return 0;
};

BPF_PERF_OUTPUT(comm_events);

int syscall__execve(struct pt_regs *ctx,
	const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct comm_event event = {
		.pid = pid,
		.type = TYPE_ENTER,
	};

	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	pid2comm_map.update(&pid, &event);
	comm_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}

int syscall__ret_execve(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	pid2comm_map.delete(&pid);

	struct comm_event event = {
		.pid = pid,
		.type = TYPE_RETURN,
	};

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	comm_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}
