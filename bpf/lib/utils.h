/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_UTILS_H_
#define __LIB_UTILS_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "endian.h"
#include "time.h"
#include "static_data.h"

#define min(x, y)		\
({				\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y;	\
})

#define max(x, y)		\
({				\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y;	\
})

#endif /* __LIB_UTILS_H_ */
