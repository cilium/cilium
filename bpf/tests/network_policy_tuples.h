/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Arrays are generated in pkg/policy/aggregate_test.go */

static __u32 aggregate_nid_in[] = {
#include "aggregate_nid_in.txt"
};

static __u32 aggregate_nid_out[] = {
#include "aggregate_nid_out.txt"
};
