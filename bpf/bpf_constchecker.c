// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "lib/endian.h"
#include "lib/common.h"

/* const values that we want to check for compatibility with Go code */
const __u8 svc_flag_external_ip  = SVC_FLAG_EXTERNAL_IP;
const __u8 svc_flag_nodeport     = SVC_FLAG_NODEPORT;
const __u8 svc_flag_local_scope  = SVC_FLAG_LOCAL_SCOPE;
const __u8 svc_flag_hostport     = SVC_FLAG_HOSTPORT;
const __u8 svc_flag_affinity     = SVC_FLAG_AFFINITY;
const __u8 svc_flag_loadbalancer = SVC_FLAG_LOADBALANCER;
const __u8 svc_flag_routable     = SVC_FLAG_ROUTABLE;
