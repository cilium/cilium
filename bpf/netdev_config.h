/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#define DROP_NOTIFY
#ifndef SKIP_DEBUG
#define DEBUG
#endif
#define ENCAP_IFINDEX 1
#define SECLABEL 2
#define SECLABEL_NB 0xfffff
#define CALLS_MAP test_cilium_calls_65535
