/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/section.h>

char attachment_context[256];

#define TC_ACT_UNSPEC	-1
#define SYS_PROCEED	1

# define printk(fmt, ...)					\
		({						\
			const char ____fmt[] = fmt;		\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})


