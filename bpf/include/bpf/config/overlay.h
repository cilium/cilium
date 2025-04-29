/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to overlay traffic (bpf_overlay.c). Do not
 * import into any other program.
 */

 #pragma once

 #include <lib/static_data.h>

/* Strict mode configuration */
DECLARE_CONFIG(bool, encryption_strict_ingress, "Enable strict encryption for ingress traffic")
