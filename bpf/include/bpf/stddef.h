/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef __BPF_STDDEF_H_
#define __BPF_STDDEF_H_


#define bool	_Bool

enum {
	false	= 0,
	true	= 1,
};

#endif /* __BPF_STDDEF_H_ */
