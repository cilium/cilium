/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#include "lib/utils.h"

#ifndef SKIP_DEBUG
#define DEBUG
#endif
#define DROP_NOTIFY
#define TRACE_NOTIFY

#define LOCAL_DELIVERY_METRICS
