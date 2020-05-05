/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_STDDEF_H_
#define __BPF_STDDEF_H_

#define NULL	((void *)0)

#define bool	_Bool

enum {
	false	= 0,
	true	= 1,
};

#endif /* __BPF_STDDEF_H_ */
