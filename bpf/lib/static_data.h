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
#define DECLARE_CONFIG(type, name, description) \
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
	__attribute__((btf_decl_tag("kind:object"))) \
	/* Assign the config variable a BTF decl tag containing its description. This
	 * allows including doc comments in code generated from BTF.
	 */ \
	__attribute__((btf_decl_tag(description))) \
	/* Declare a global variable of the given name and type. volatile to
	 * prevent the compiler from eliding all accesses, which would also
	 * omit it from the ELF.
	 */ \
	volatile const type __config_##name;

/* Declare a global node-level configuration variable that is emitted to a
 * separate Go config struct embedded into all individual object configs. Access
 * the variable using the CONFIG() macro.
 */
#define NODE_CONFIG(type, name, description) \
	__section(__CONFIG_SECTION) \
	/* Tag this variable as being a node-level variable. dpgen will emit
	 * these to a node-specific Go struct that can be embedded into
	 * object-level configuration structs. */ \
	__attribute__((btf_decl_tag("kind:node"))) \
	__attribute__((btf_decl_tag(description))) \
	volatile const type __config_##name;

/* Hardcode config values at compile time, e.g. from per-endpoint headers.
 * Can be used only once per config variable within a single compilation unit.
 */
#define ASSIGN_CONFIG(type, name, value) \
	/* Emit a reference to the variable before assigning a value. Without
	 * this, we risk silently declaring and defining a variable that didn't
	 * exist before. */ \
	void __check_##name(void) \
	{ CONFIG(name); /* Error: variable was assigned before declaring. */ }; \
	volatile const type __config_##name = value;

/* Access a global configuration variable declared using DECLARE_CONFIG(). All
 * accesses must be done through this macro to ensure the loader's dead code
 * elimination can recognize them.
 */
#define CONFIG(name) __config_##name
