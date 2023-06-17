/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __STUBS_H_
#define __STUBS_H_

/* Define dummy values to make bpf_{lxc,overlay}.c to compile */
#ifdef ENABLE_NODEPORT
# ifndef NATIVE_DEV_IFINDEX
#  define NATIVE_DEV_IFINDEX 0
# endif
# ifndef DSR_ENCAP_MODE
#  define DSR_ENCAP_MODE 0
#  define DSR_ENCAP_IPIP 2
#  define DSR_ENCAP_GENEVE 3
# endif
# if defined(ENABLE_MASQUERADE_IPV4) && !defined(IPV4_MASQUERADE)
#  define IPV4_MASQUERADE 0
# endif
# ifndef IPV4_DIRECT_ROUTING
#  define IPV4_DIRECT_ROUTING 0
# endif
# if defined(ENABLE_MASQUERADE_IPV6) && !defined(IPV6_MASQUERADE_V)
DEFINE_IPV6(IPV6_MASQUERADE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
#  define IPV6_MASQUERADE_V
# endif
#endif

#endif /* __STUBS_H_ */
