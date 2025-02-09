/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Define dummy values to make bpf_{lxc,overlay}.c to compile */
#ifdef ENABLE_NODEPORT
# ifndef DSR_ENCAP_MODE
#  define DSR_ENCAP_MODE 0
#  define DSR_ENCAP_IPIP 2
#  define DSR_ENCAP_GENEVE 3
# endif
# ifndef IPV4_DIRECT_ROUTING
#  define IPV4_DIRECT_ROUTING 0
# endif
#endif
