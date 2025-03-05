/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include "endian.h"

#define __CONFIG_SECTION ".rodata.config"

/* Declare a global configuration variable that can be modified at runtime,
 * without needing to recompile the datapath. Access the variable using the
 * CONFIG() macro.
 */
#define _DECLARE_CONFIG(type, name, description, kind) \
	/* Emit the variable to the .rodata.config section. The compiler will emit a
	 * BTF Datasec referring to all variables in this section, making them
	 * convenient to iterate through for generating config scaffolding in Go.
	 * ebpf-go will expose these in CollectionSpec.Variables.
	 */ \
	__section(__CONFIG_SECTION) \
	/* Config struct generation for bpf objects like bpf_lxc or bpf_host,
	 * selects only these variables. Node configs use a different kind and
	 * are emitted to another struct.
	 */ \
	__attribute__((btf_decl_tag("kind:" kind))) \
	/* Assign the config variable a BTF decl tag containing its description. This
	 * allows including doc comments in code generated from BTF.
	 */ \
	__attribute__((btf_decl_tag(description))) \
	/* Declare a global variable of the given name and type. volatile to
	 * prevent the compiler from eliding all accesses, which would also
	 * omit it from the ELF.
	 */ \
	volatile const type __config_##name;

#define DECLARE_CONFIG(type, name, description) \
	_DECLARE_CONFIG(type, name, description, "object")
#define DECLARE_NODE_CONFIG(type, name, description) \
	_DECLARE_CONFIG(type, name, description, "node")
/* Hardcode config values at compile time, e.g. from per-endpoint headers.
 * Can be used only once per config variable within a single compilation unit.
 */
#define ASSIGN_CONFIG(type, name, value) \
	volatile const type __config_##name = value;

/* Access a global configuration variable declared using DECLARE_CONFIG(). All
 * accesses must be done through this macro to ensure the loader's dead code
 * elimination can recognize them.
 */
#define CONFIG(name) __config_##name

/* Deprecated, use CONFIG instead. */
#define fetch_ipv6(x) CONFIG(x ## _1), CONFIG(x ## _2)
#define fetch_mac(x) { { CONFIG(x ## _1), (__u16)CONFIG(x ## _2) } }

/* DEFINE_IPV6 is used to assign values to global constants from
 * C headers generated at runtime before the datapath is compiled.
 */
#define DEFINE_IPV6(name, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) \
	DECLARE_CONFIG(__u64, name##_1, "First half of ipv6 address " #name) \
	DECLARE_CONFIG(__u64, name##_2, "Second half of ipv6 address " #name) \
	ASSIGN_CONFIG(__u64, name##_1, bpf_cpu_to_be64( \
			(__u64)(__u8)(a1) << 56 | (__u64)(__u8)(a2) << 48 | \
			(__u64)(__u8)(a3) << 40 | (__u64)(__u8)(a4) << 32 | \
			(__u64)(__u8)(a5) << 24 | (__u64)(__u8)(a6) << 16 | \
			(__u64)(__u8)(a7) << 8  | (__u64)(__u8)(a8))); \
	ASSIGN_CONFIG(__u64, name##_2, bpf_cpu_to_be64( \
			(__u64)(__u8)(a9) << 56  | (__u64)(__u8)(a10) << 48 | \
			(__u64)(__u8)(a11) << 40 | (__u64)(__u8)(a12) << 32 | \
			(__u64)(__u8)(a13) << 24 | (__u64)(__u8)(a14) << 16 | \
			(__u64)(__u8)(a15) << 8  | (__u64)(__u8)(a16)));
