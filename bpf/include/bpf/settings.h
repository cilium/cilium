/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_SETTINGS_H_
#define __LIB_SETTINGS_H_

#include <bpf/compiler.h>

#define SETTING_HARDCODED(name, val) \
	static __always_inline unsigned long long setting_##name(void)\
	{ \
		return val; \
	} \

#define SETTING(name) \
	static __always_inline unsigned long long setting_##name(void)\
	{ \
		unsigned long long val; \
		asm volatile(__stringify(%0 = setting_##name ll)  : "=r"(val)); \
		return val; \
	} \

#ifdef setting_l2_announcement_val
SETTING_HARDCODED(l2_announcement, setting_l2_announcement_val)
#else
SETTING(l2_announcement)
#endif

#endif /* __LIB_SETTINGS_H_ */
