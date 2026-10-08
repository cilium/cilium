/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "../helpers_sock.h"

#define __ctx_sock bpf_sock_addr
#undef ctx_event_output
#define ctx_event_output sock_event_output
