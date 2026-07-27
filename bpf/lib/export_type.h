/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Export and generate a Go type definition for this type. Only use this if the
 * type is not already referenced by a config variable or used as a map
 * key/value type.
 *
 * Force creating a reference to the type by declaring a global variable to
 * ensure the compiler includes it in BTF.
 */
#define EXPORT_TYPE(type) __expand_type(type, __COUNTER__)
#define __expand_type(type, n) ___expand_type(type, n)
#define ___expand_type(type, n) type __dpexp_ ## n
