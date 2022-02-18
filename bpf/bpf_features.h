/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#ifndef BPF_FEATURES_H_
#define BPF_FEATURES_H_

#define HAVE_PROG_TYPE_HELPER(prog_type, helper)	\
	BPF__PROG_TYPE_ ## prog_type ## __HELPER_ ## helper
#define BPF__PROG_TYPE_sched_cls__HELPER_bpf_skb_change_tail 1

#endif /* BPF_FEATURES_H_ */
