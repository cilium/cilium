/*
 *  Copyright (C) 2016-2020 Authors of Cilium
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
#ifndef ENOTSUP
# define ENOTSUP	95
#endif
#ifndef EADDRINUSE
# define EADDRINUSE	98
#endif

#endif /* __BPF_ERRNO__ */
