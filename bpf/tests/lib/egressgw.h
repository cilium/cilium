/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

enum egressgw_test {
	TEST_SNAT1                    = 0,
	TEST_SNAT2                    = 1,
	TEST_SNAT_EXCL_CIDR           = 2,
	TEST_REDIRECT                 = 3,
	TEST_REDIRECT_EXCL_CIDR       = 4,
	TEST_REDIRECT_SKIP_NO_GATEWAY = 5,
	TEST_XDP_REPLY                = 6,
};

