/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_SECTION__
#define __BPF_SECTION__

#include "compiler.h"

#ifndef __section_tail
# define __section_tail(ID, KEY)	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_license
# define __section_license		__section("license")
#endif

#ifndef __section_maps
# define __section_maps			__section("maps")
#endif

#ifndef __section_maps_btf
# define __section_maps_btf		__section(".maps")
#endif

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME)				\
	char ____license[] __section_license = NAME
#endif

#endif /* __BPF_SECTION__ */
