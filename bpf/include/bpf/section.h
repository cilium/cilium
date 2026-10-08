/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "compiler.h"

/* All non-inlined functions in bpf need a program type, communicated through
 * the function's ELF section name. This changes based on the type of context
 * the object was built for, either tc(x) or xdp.
 *
 * __section_entry is the default and should be used for entry points (programs
 * attached directly to bpf hooks) as well as mock tail calls in bpf tests.
 *
 * For marking tail calls in regular, non-test code, use __declare_tail defined
 * in tailcall.h.
 */
#if !defined(PROG_TYPE)
	#error "Include bpf/ctx/skb.h or xdp.h before section.h!"
#endif
#define __section_entry		__section(PROG_TYPE "/entry")

#define __section_license	__section("license")
#define __section_maps_btf	__section(".maps")

#define BPF_LICENSE(NAME) \
	char ____license[] __section_license = NAME
