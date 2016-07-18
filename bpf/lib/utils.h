#ifndef __LIB_UTILS_H_
#define __LIB_UTILS_H_

#include <bpf/api.h>

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

#endif
