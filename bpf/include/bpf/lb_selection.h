/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 * Load balancing algorithms. The "first" algorithm is only used in tests,
 * this is not possible to select it from the agent.
 */
#define LB_SELECTION_RANDOM 1
#define LB_SELECTION_MAGLEV 2
#define LB_SELECTION_FIRST  3
