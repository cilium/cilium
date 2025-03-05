// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define TUNNEL_MODE
#define ENABLE_ENDPOINT_ROUTES 1

#define EXPECTED_STATUS_CODE CTX_ACT_REDIRECT

#include "ipsec_from_host_generic.h"
