/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* We do not care which context we need in this case, but it must be
 * something compilable, thus we reuse skb ctx here.
 */

#include "skb.h"
