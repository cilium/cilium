/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/api.h>

#include "endian.h"

/* Declare a global configuration variable that can be modified at runtime,
 * without needing to recompile the datapath. Access the variable using the
 * CONFIG() macro.
 */
#define DECLARE_CONFIG(type, name, description) \
	/* Emit the variable to the .rodata.config section. The compiler will emit a
	 * BTF Datasec referring to all variables in this section, making them
	 * convenient to iterate through for generating config scaffolding in Go.
	 * ebpf-go will expose these in CollectionSpec.Variables.
	 */ \
	__section(".rodata.config") \
	/* Assign the config variable a BTF decl tag containing its description. This
	 * allows including doc comments in code generated from BTF.
	 */ \
	__attribute__((btf_decl_tag(description))) \
	/* Declare a global variable of the given name and type. volatile to
	 * prevent the compiler from eliding all accesses, which would also
	 * omit it from the ELF.
	 */ \
	volatile const type __config_##name;

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
#define fetch_u16(x) CONFIG(x)
#define fetch_u32(x) CONFIG(x)
#define fetch_u64(x) CONFIG(x)
#define fetch_ipv6(x) CONFIG(x ## _1), CONFIG(x ## _2)
#define fetch_mac(x) { { CONFIG(x ## _1), (__u16)CONFIG(x ## _2) } }

/* Deprecated, use DECLARE_CONFIG instead. */
#define DEFINE_U16(name, value) \
	DECLARE_CONFIG(__u16, name, "Constant " #name " declared using DEFINE_U16") \
	ASSIGN_CONFIG(__u16, name, value)
#define DEFINE_U32(name, value) \
	DECLARE_CONFIG(__u32, name, "Constant " #name " declared using DEFINE_U32") \
	ASSIGN_CONFIG(__u32, name, value)
#define DEFINE_U64(name, value) \
	DECLARE_CONFIG(__u64, name, "Constant " #name " declared using DEFINE_U64") \
	ASSIGN_CONFIG(__u64, name, value)

/* DEFINE_IPV6 and DEFINE_MAC are used to assign values to global constants from
 * C headers generated at runtime before the datapath is compiled. This data
 * ends up in .rodata.config in the ELF and is also inlined by the Go loader,
 * even though it's not handled by ELF variable substitution.
 *
 * Variables relying on this are THIS_INTERFACE_MAC, LXC_IP, IPV6_MASQUERADE, ROUTER_IP.
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

#define DEFINE_MAC(name, a1, a2, a3, a4, a5, a6) \
	DECLARE_CONFIG(__u32, name##_1, "First 32 bits of mac address " #name) \
	DECLARE_CONFIG(__u32, name##_2, "Remaining 16 bits of mac address " #name) \
	ASSIGN_CONFIG(__u32, name##_1, \
			(__u32)(__u8)(a1) << 24 | (__u32)(__u8)(a2) << 16 | \
			(__u32)(__u8)(a3) << 8  | (__u32)(__u8)(a4)) \
	ASSIGN_CONFIG(__u32, name##_2, (__u32)(__u8)(a5) << 8  | (__u32)(__u8)(a6))
