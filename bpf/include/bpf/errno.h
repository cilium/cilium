/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_ERRNO__
#define __BPF_ERRNO__

/* Few basic errno codes as we don't want to include errno.h. */

#ifndef EPERM
# define EPERM		1
#endif
#ifndef ENOENT
# define ENOENT		2
#endif
#ifndef ENXIO
# define ENXIO		6
#endif
#ifndef ENOMEM
# define ENOMEM		12
#endif
#ifndef EFAULT
# define EFAULT		14
#endif
#ifndef EINVAL
# define EINVAL		22
#endif
#ifndef ENOTSUP
# define ENOTSUP	95
#endif
#ifndef EADDRINUSE
# define EADDRINUSE	98
#endif
#ifndef ECONNRESET
# define ECONNRESET	104
#endif
#ifndef ENOBUFS
# define ENOBUFS	105
#endif
#ifndef ENOTCONN
# define ENOTCONN	107
#endif
#ifndef ECONNREFUSED
# define ECONNREFUSED	111
#endif
#ifndef EHOSTUNREACH
# define EHOSTUNREACH	113
#endif
#ifndef ENOTSUPP
# define ENOTSUPP	524
#endif

#endif /* __BPF_ERRNO__ */
