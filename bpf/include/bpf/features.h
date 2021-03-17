/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef ____BPF_FEATURES____
#define ____BPF_FEATURES____

#include <bpf_features.h>

/* Neither skb nor xdp related features. */

/* Testing both here since both were added to the same kernel release
 * and we need to ensure both are enabled.
 */
#if HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_get_netns_cookie) && \
    HAVE_PROG_TYPE_HELPER(cgroup_sock,      bpf_get_netns_cookie)
# define BPF_HAVE_NETNS_COOKIE 1
#endif

#if HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_get_socket_cookie)
# define BPF_HAVE_SOCKET_COOKIE 1
#endif

#if HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_jiffies64) && \
    HAVE_PROG_TYPE_HELPER(cgroup_sock,      bpf_jiffies64) && \
    HAVE_PROG_TYPE_HELPER(sched_cls,        bpf_jiffies64) && \
    HAVE_PROG_TYPE_HELPER(xdp,              bpf_jiffies64)
# define BPF_HAVE_JIFFIES 1
#endif

#if HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_ktime_get_boot_ns) && \
    HAVE_PROG_TYPE_HELPER(cgroup_sock,      bpf_ktime_get_boot_ns) && \
    HAVE_PROG_TYPE_HELPER(sched_cls,        bpf_ktime_get_boot_ns) && \
    HAVE_PROG_TYPE_HELPER(xdp,              bpf_ktime_get_boot_ns)
# define BPF_HAVE_BOOT_TIME 1
#endif

#if HAVE_PROG_TYPE_HELPER(sched_cls, bpf_csum_level)
# define BPF_HAVE_CSUM_LEVEL 1
#endif

#if HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_sk_lookup_tcp) && \
    HAVE_PROG_TYPE_HELPER(cgroup_sock_addr, bpf_sk_lookup_udp)
# define BPF_HAVE_SOCKET_LOOKUP 1
#endif

#endif /* ____BPF_FEATURES____ */
